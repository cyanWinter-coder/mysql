// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
)

// newReuseTestConn returns a mysqlConn backed by nc with both netConn and
// rawConn set, so cleanup() really closes nc (as in production connections).
func newReuseTestConn(nc net.Conn) *mysqlConn {
	cfg := NewConfig()
	cfg.Logger = &NopLogger{}
	if err := cfg.normalize(); err != nil {
		panic(err)
	}
	return &mysqlConn{
		buf:              newBuffer(),
		cfg:              cfg,
		netConn:          nc,
		rawConn:          nc,
		closech:          make(chan struct{}),
		maxAllowedPacket: defaultMaxAllowedPacket,
	}
}

// assertConnUnusable verifies that a connection which failed mid-response is
// marked non-reusable for the connection pool.
func assertConnUnusable(t *testing.T, mc *mysqlConn) {
	t.Helper()
	if !mc.closed.Load() {
		t.Error("connection must be closed after an incomplete response")
	}
	if mc.IsValid() {
		t.Error("IsValid must report false for a desynchronized connection")
	}
	if err := mc.ResetSession(context.Background()); err != driver.ErrBadConn {
		t.Errorf("ResetSession must return driver.ErrBadConn, got %#v", err)
	}
}

// assertConnReusable verifies that a connection in a clean state is kept
// eligible for reuse.
func assertConnReusable(t *testing.T, mc *mysqlConn) {
	t.Helper()
	if mc.closed.Load() {
		t.Error("connection must stay open")
	}
	if !mc.IsValid() {
		t.Error("IsValid must report true for a clean connection")
	}
	if err := mc.ResetSession(context.Background()); err != nil {
		t.Errorf("ResetSession must succeed for a clean connection, got %#v", err)
	}
}

func makeErrPacket(seq byte, errno uint16, msg string) []byte {
	payload := []byte{0xff, byte(errno), byte(errno >> 8), '#'}
	payload = append(payload, "HY000"...)
	payload = append(payload, msg...)
	return makePacket(seq, payload)
}

// OK packet: 0x00, affected_rows=0, last_insert_id=0, status=0x0002, warnings=0.
func makeOKPacket(seq byte) []byte {
	return makePacket(seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
}

// TestHalfPacketClosesConnection feeds a packet whose announced body never
// fully arrives. The connection must not be reused: unconsumed bytes would
// otherwise leak into the next command issued through the pool.
func TestHalfPacketClosesConnection(t *testing.T) {
	conn := new(mockConn)
	// Header announces 10 payload bytes, only 2 arrive before reads fail.
	conn.data = []byte{0x0a, 0x00, 0x00, 0x01, 0xaa, 0xbb}
	conn.maxReads = 1

	mc := newReuseTestConn(conn)
	_, err := mc.readPacket()
	if !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("expected ErrInvalidConn, got %#v", err)
	}
	assertConnUnusable(t, mc)
}

// TestReadTimeoutClosesConnection simulates a read that fails with a
// network timeout in the middle of a response.
func TestReadTimeoutClosesConnection(t *testing.T) {
	timeoutErr := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	conn := &chunkedConn{chunks: [][]byte{}} // no data at all
	mc := newReuseTestConn(conn)
	mc.netConn = &errReaderConn{Conn: conn, err: timeoutErr}
	mc.rawConn = mc.netConn

	_, err := mc.readPacket()
	if !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("expected ErrInvalidConn, got %#v", err)
	}
	assertConnUnusable(t, mc)
}

// errReaderConn fails every Read with err.
type errReaderConn struct {
	net.Conn
	err error
}

func (c *errReaderConn) Read([]byte) (int, error) { return 0, c.err }

// TestSplitPacketReassembly verifies that a logical packet split across
// multiple maxPacketSize frames is reassembled and leaves the connection
// reusable.
func TestSplitPacketReassembly(t *testing.T) {
	t.Run("continuation", func(t *testing.T) {
		payload := bytes.Repeat([]byte("x"), maxPacketSize+5)
		conn := new(mockConn)
		conn.data = append(makePacket(1, payload[:maxPacketSize]), makePacket(2, payload[maxPacketSize:])...)

		mc := newReuseTestConn(conn)
		mc.sequence = 1
		data, err := mc.readPacket()
		if err != nil {
			t.Fatalf("readPacket failed: %v", err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatalf("reassembled payload mismatch: got %d bytes", len(data))
		}
		assertConnReusable(t, mc)
	})

	t.Run("zero length terminator", func(t *testing.T) {
		payload := bytes.Repeat([]byte("y"), maxPacketSize)
		conn := new(mockConn)
		conn.data = append(makePacket(1, payload), makePacket(2, nil)...)

		mc := newReuseTestConn(conn)
		mc.sequence = 1
		data, err := mc.readPacket()
		if err != nil {
			t.Fatalf("readPacket failed: %v", err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatalf("reassembled payload mismatch: got %d bytes", len(data))
		}
		assertConnReusable(t, mc)
	})

	t.Run("truncated continuation", func(t *testing.T) {
		conn := new(mockConn)
		// Announces a maxPacketSize body but the connection dies right away.
		conn.data = []byte{0xff, 0xff, 0xff, 0x01, 0xaa, 0xbb}
		conn.maxReads = 1

		mc := newReuseTestConn(conn)
		_, err := mc.readPacket()
		if !errors.Is(err, ErrInvalidConn) {
			t.Fatalf("expected ErrInvalidConn, got %#v", err)
		}
		assertConnUnusable(t, mc)
	})
}

// TestCancelDuringQueryResponse cancels a query while the multi-packet
// response is only partially consumed. The connection must be closed instead
// of returning to the pool with unread packets.
func TestCancelDuringQueryResponse(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	mc := newReuseTestConn(client)
	mc.startWatcher()
	defer mc.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delivered := make(chan struct{})
	go func() {
		// Read the COM_QUERY packet, deliver only the column-count packet
		// of a 2-column result set, then stall: the rest never arrives.
		if _, err := server.Read(make([]byte, 64)); err != nil {
			return
		}
		server.Write(makePacket(1, []byte{0x02}))
		close(delivered)
		<-ctx.Done()
	}()

	if err := mc.watchCancel(ctx); err != nil {
		t.Fatal(err)
	}
	errch := make(chan error, 1)
	go func() {
		_, err := mc.query("SELECT 1", nil)
		errch <- err
	}()

	// Cancel only after the partial response was consumed and the query
	// is blocked waiting for column definitions that never arrive.
	<-delivered
	cancel()
	if err := <-errch; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %#v", err)
	}
	assertConnUnusable(t, mc)
}

// TestCancelDuringPrepare cancels a Prepare whose response never arrives.
func TestCancelDuringPrepare(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	mc := newReuseTestConn(client)
	mc.startWatcher()
	defer mc.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Swallow COM_STMT_PREPARE, then cancel without ever answering.
		if _, err := server.Read(make([]byte, 64)); err != nil {
			return
		}
		cancel()
		<-ctx.Done()
	}()

	_, err := mc.PrepareContext(ctx, "SELECT 1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %#v", err)
	}
	assertConnUnusable(t, mc)
}

// TestServerErrorKeepsConnectionReusable verifies that a complete ERR packet
// from the server is a statement-level error: the response is fully consumed,
// so the connection stays in the pool.
func TestServerErrorKeepsConnectionReusable(t *testing.T) {
	conn := new(mockConn)
	// One reply per issued command: an ERR packet, then an OK packet.
	conn.queuedReplies = [][]byte{makeErrPacket(1, 1064, "syntax error"), makeOKPacket(1)}

	mc := newReuseTestConn(conn)

	_, err := mc.query("SELECT broken", nil)
	var merr *MySQLError
	if !errors.As(err, &merr) {
		t.Fatalf("expected *MySQLError, got %#v", err)
	}
	if merr.Number != 1064 {
		t.Fatalf("unexpected error number: %d", merr.Number)
	}
	assertConnReusable(t, mc)

	// The same connection must serve the next command.
	rows, err := mc.query("SELECT 1", nil)
	if err != nil {
		t.Fatalf("reused connection failed: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("rows.Close failed: %v", err)
	}
	assertConnReusable(t, mc)
}

// TestMalformedPacketsCloseConnection checks that protocol-level validation
// failures poison the connection, independent of which packet type is hit.
func TestMalformedPacketsCloseConnection(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		read    func(mc *mysqlConn) error
	}{
		{
			name:    "truncated OK packet",
			payload: []byte{0x00, 0x00},
			read:    func(mc *mysqlConn) error { return mc.clearResult().readResultOK() },
		},
		{
			name:    "OK packet missing status",
			payload: []byte{0x00, 0x00, 0x00},
			read:    func(mc *mysqlConn) error { return mc.clearResult().readResultOK() },
		},
		{
			name:    "malformed ERR packet",
			payload: []byte{0xff, 0x01},
			read:    func(mc *mysqlConn) error { return mc.clearResult().readResultOK() },
		},
		{
			name:    "truncated column count",
			payload: []byte{0xfc, 0x01},
			read: func(mc *mysqlConn) error {
				_, _, err := mc.clearResult().readResultSetHeaderPacket()
				return err
			},
		},
		{
			name:    "short prepare OK packet",
			payload: []byte{0x00, 0x01},
			read: func(mc *mysqlConn) error {
				stmt := &mysqlStmt{mc: mc}
				_, err := stmt.readPrepareResultPacket()
				return err
			},
		},
		{
			name:    "truncated column definition",
			payload: []byte{0x05, 'd', 'e'}, // announces 5-byte catalog, sends 2
			read: func(mc *mysqlConn) error {
				_, err := mc.readColumns(1, nil)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := new(mockConn)
			conn.data = makePacket(1, tc.payload)

			mc := newReuseTestConn(conn)
			mc.sequence = 1

			if err := tc.read(mc); err == nil {
				t.Fatal("expected an error")
			}
			assertConnUnusable(t, mc)
		})
	}
}

// TestPrepareResponseFailures covers interrupted Prepare: transport failure
// poisons the connection, a server SQL error does not.
func TestPrepareResponseFailures(t *testing.T) {
	t.Run("read failure closes connection", func(t *testing.T) {
		conn := new(mockConn)
		conn.maxReads = 1 // first read returns 0 bytes, second fails

		mc := newReuseTestConn(conn)
		_, err := mc.Prepare("SELECT ?")
		if !errors.Is(err, ErrInvalidConn) {
			t.Fatalf("expected ErrInvalidConn, got %#v", err)
		}
		assertConnUnusable(t, mc)
	})

	t.Run("server error keeps connection", func(t *testing.T) {
		conn := new(mockConn)
		conn.data = makeErrPacket(1, 1146, "table does not exist")

		mc := newReuseTestConn(conn)
		_, err := mc.Prepare("SELECT * FROM missing")
		var merr *MySQLError
		if !errors.As(err, &merr) {
			t.Fatalf("expected *MySQLError, got %#v", err)
		}
		assertConnReusable(t, mc)
	})
}

// TestBeginTxResponseFailures covers interrupted BeginTx: transport failure
// poisons the connection, a server SQL error does not.
func TestBeginTxResponseFailures(t *testing.T) {
	t.Run("read failure closes connection", func(t *testing.T) {
		conn := new(mockConn)
		conn.maxReads = 1

		mc := newReuseTestConn(conn)
		_, err := mc.BeginTx(context.Background(), driver.TxOptions{})
		if !errors.Is(err, ErrInvalidConn) {
			t.Fatalf("expected ErrInvalidConn, got %#v", err)
		}
		assertConnUnusable(t, mc)
	})

	t.Run("server error keeps connection", func(t *testing.T) {
		conn := new(mockConn)
		conn.data = makeErrPacket(1, 1565, "cannot start transaction")

		mc := newReuseTestConn(conn)
		_, err := mc.BeginTx(context.Background(), driver.TxOptions{})
		var merr *MySQLError
		if !errors.As(err, &merr) {
			t.Fatalf("expected *MySQLError, got %#v", err)
		}
		assertConnReusable(t, mc)
	})
}

// TestCompressedFrameLengthMismatch verifies that a compressed frame whose
// announced uncompressed length does not match the decoded payload poisons
// the connection.
func TestCompressedFrameLengthMismatch(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), 1024)

	_, cSend := newRWMockConn(0)
	cSend.compress = true
	cSend.compIO = newCompIO(cSend)
	frame := compressHelper(t, cSend, payload)

	// Corrupt the announced uncompressed length. The compressed frame wraps
	// the whole MySQL packet, 4-byte packet header included.
	uncompressedLen := getUint24(frame[4:7])
	if uncompressedLen != len(payload)+4 {
		t.Fatalf("test setup: unexpected uncompressed length %d", uncompressedLen)
	}
	putUint24(frame[4:7], uncompressedLen+1)

	conn := new(mockConn)
	conn.data = frame
	mc := newReuseTestConn(conn)
	mc.compress = true
	mc.compIO = newCompIO(mc)

	if _, err := mc.readPacket(); err == nil {
		t.Fatal("expected an error for a length-mismatched compressed frame")
	}
	assertConnUnusable(t, mc)
}

// TestCompressedResponseReusable verifies that well-formed compressed frames
// (including an actually zlib-compressed payload and sequence continuity
// across frames) keep the connection reusable.
func TestCompressedResponseReusable(t *testing.T) {
	_, cSend := newRWMockConn(0)
	cSend.compress = true
	cSend.compIO = newCompIO(cSend)

	// One frame with a payload large enough to be really compressed,
	// followed by two small OK packets in their own frames.
	bigPayload := bytes.Repeat([]byte("q"), 1024)
	stream := compressHelper(t, cSend, bigPayload)
	okPayload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	stream = append(stream, compressHelper(t, cSend, okPayload)...)
	stream = append(stream, compressHelper(t, cSend, okPayload)...)

	conn := new(mockConn)
	conn.data = stream
	mc := newReuseTestConn(conn)
	mc.compress = true
	mc.compIO = newCompIO(mc)

	data, err := mc.readPacket()
	if err != nil {
		t.Fatalf("readPacket failed: %v", err)
	}
	if !bytes.Equal(data, bigPayload) {
		t.Fatalf("payload mismatch: got %d bytes", len(data))
	}

	handleOk := mc.clearResult()
	for i := range 2 {
		if err := handleOk.readResultOK(); err != nil {
			t.Fatalf("readResultOK %d failed: %v", i, err)
		}
	}
	if mc.sequence != 3 || mc.compressSequence != 3 {
		t.Fatalf("sequence desync: sequence=%d compressSequence=%d", mc.sequence, mc.compressSequence)
	}
	assertConnReusable(t, mc)
}

// TestChunkedDelivery mirrors TLS transports, where a server write maps to
// one TLS record and reads return record-sized chunks. Reuse semantics must
// match the plain-transport behavior.
func TestChunkedDelivery(t *testing.T) {
	t.Run("complete response in small chunks", func(t *testing.T) {
		pkt := makeOKPacket(1)
		chunks := make([][]byte, 0, len(pkt))
		for _, b := range pkt {
			chunks = append(chunks, []byte{b})
		}
		conn := &chunkedConn{chunks: chunks}

		mc := newReuseTestConn(conn)
		mc.sequence = 1
		if err := mc.clearResult().readResultOK(); err != nil {
			t.Fatalf("readResultOK failed: %v", err)
		}
		assertConnReusable(t, mc)
	})

	t.Run("half packet across chunk boundary", func(t *testing.T) {
		pkt := makeOKPacket(1)
		// Deliver the header and half the body, then the transport dies.
		conn := &chunkedConn{chunks: [][]byte{pkt[:4], pkt[4:6]}}

		mc := newReuseTestConn(conn)
		mc.sequence = 1
		if err := mc.clearResult().readResultOK(); !errors.Is(err, ErrInvalidConn) {
			t.Fatalf("expected ErrInvalidConn, got %#v", err)
		}
		assertConnUnusable(t, mc)
	})
}

// reuseTestConnector hands out scripted mysqlConns to database/sql and
// counts how many physical connections were opened. Each script is a list of
// connections; each connection is a list of replies, one per client command.
type reuseTestConnector struct {
	mu       sync.Mutex
	scripts  [][][]byte
	connects int
}

func (c *reuseTestConnector) Connect(context.Context) (driver.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.scripts) == 0 {
		return nil, errors.New("no scripted connection left")
	}
	replies := c.scripts[0]
	c.scripts = c.scripts[1:]
	c.connects++
	return newReuseTestConn(&mockConn{queuedReplies: replies}), nil
}

func (c *reuseTestConnector) Driver() driver.Driver { return &MySQLDriver{} }

func (c *reuseTestConnector) numConnects() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connects
}

// TestPoolReuseAfterServerError proves through database/sql that a complete
// server SQL error does not cost a physical connection.
func TestPoolReuseAfterServerError(t *testing.T) {
	connector := &reuseTestConnector{scripts: [][][]byte{
		{makeErrPacket(1, 1064, "syntax error"), makeOKPacket(1)},
	}}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)

	_, err := db.QueryContext(context.Background(), "SELECT broken")
	var merr *MySQLError
	if !errors.As(err, &merr) {
		t.Fatalf("expected *MySQLError, got %#v", err)
	}

	rows, err := db.QueryContext(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	rows.Close()

	if n := connector.numConnects(); n != 1 {
		t.Fatalf("server SQL error must not drop the connection: %d connects", n)
	}
}

// TestPoolDiscardsDesyncedConnection proves through database/sql that a
// connection whose response stream broke mid-way is discarded and replaced.
func TestPoolDiscardsDesyncedConnection(t *testing.T) {
	// Column count 1 followed by a truncated column definition.
	badResponse := append(makePacket(1, []byte{0x01}), makePacket(2, []byte{0x05, 'd', 'e'})...)
	connector := &reuseTestConnector{scripts: [][][]byte{
		{badResponse},
		{makeOKPacket(1)},
	}}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)

	_, err := db.QueryContext(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected an error for the malformed response")
	}

	rows, err := db.QueryContext(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	rows.Close()

	if n := connector.numConnects(); n != 2 {
		t.Fatalf("desynchronized connection must be replaced: %d connects", n)
	}
}

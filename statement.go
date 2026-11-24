// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

type mysqlStmt struct {
	mc          *mysqlConn
	id          uint32
	paramCount  int
	columns     []mysqlField
	queryString string

	closeMu sync.Mutex
	closed  bool
	refs    *stmtRefs
}

// stmtRefs counts Prepare handles that share one server-side statement ID.
type stmtRefs struct {
	mu    sync.Mutex
	count int
}

func (r *stmtRefs) retain() {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
}

// release decrements the count and reports whether the server statement must
// now be closed.
func (r *stmtRefs) release() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count--
	return r.count <= 0
}

// newHandle creates an independent Close handle for a shared statement. The
// protocol fields are copied; Close state is not shared.
func (stmt *mysqlStmt) newHandle() *mysqlStmt {
	return &mysqlStmt{
		mc:          stmt.mc,
		id:          stmt.id,
		paramCount:  stmt.paramCount,
		columns:     stmt.columns,
		queryString: stmt.queryString,
		refs:        stmt.refs,
	}
}

func (stmt *mysqlStmt) Close() error {
	stmt.closeMu.Lock()
	defer stmt.closeMu.Unlock()

	// driver.Stmt.Close can be called more than once, thus this function has
	// to be idempotent. See also Issue #450 and golang/go#16019.
	// This bug has been fixed in Go 1.8.
	// https://github.com/golang/go/commit/90b8a0ca2d0b565c7c7199ffcf77b15ea6b6db3a
	// But we keep this function idempotent because it is safer.
	if stmt.closed {
		return nil
	}
	stmt.closed = true

	mc := stmt.mc
	query := stmt.queryString
	if mc != nil {
		// Closing any owner evicts the text from the lookup cache. Other
		// handles that already acquired the statement remain valid until they
		// are closed too.
		mc.evictStmtCache(query)
	}
	lastHandle := true
	if stmt.refs != nil {
		lastHandle = stmt.refs.release()
	}

	if mc == nil || mc.closed.Load() {
		stmt.mc = nil
		if mc != nil {
			mc.invalidateStmtCache()
		}
		return nil
	}

	if !lastHandle {
		stmt.mc = nil
		return nil
	}

	err := mc.writeCommandPacketUint32(comStmtClose, stmt.id)
	stmt.mc = nil
	return err
}

func (stmt *mysqlStmt) NumInput() int {
	return stmt.paramCount
}

// MySQL error codes that mean a server-side statement ID can no longer be
// executed even though the client connection itself is still usable.
const (
	erUnknownStmtHandler = 1243
	erNeedReprepare      = 1615
)

func staleStatementError(err error) bool {
	var merr *MySQLError
	return errors.As(err, &merr) &&
		(merr.Number == erUnknownStmtHandler || merr.Number == erNeedReprepare)
}

// reprepare replaces the server statement with a freshly prepared one using
// the original SQL text. It is used after the server invalidates a statement
// (for example after a schema change) and by reconnect/retry paths.
func (stmt *mysqlStmt) reprepare() error {
	mc := stmt.mc
	if mc == nil || mc.closed.Load() {
		return driver.ErrBadConn
	}
	if stmt.queryString == "" {
		return errors.New("mysql: cannot reprepare statement without SQL text")
	}

	newStmt, err := mc.prepare(stmt.queryString)
	if err != nil {
		return err
	}

	oldID := stmt.id
	stmt.id = newStmt.id
	stmt.paramCount = newStmt.paramCount
	stmt.columns = newStmt.columns
	stmt.closed = false
	mc.statementCache().put(stmt.queryString, stmt)

	// The old ID is no longer needed. COM_STMT_CLOSE has no response, so a
	// failure here only means the connection is already going to be discarded.
	if oldID != 0 && oldID != newStmt.id {
		if err := mc.writeCommandPacketUint32(comStmtClose, oldID); err != nil {
			mc.log("closing stale prepared statement:", err)
		}
	}
	return nil
}

func (stmt *mysqlStmt) ColumnConverter(idx int) driver.ValueConverter {
	return converter{}
}

func (stmt *mysqlStmt) CheckNamedValue(nv *driver.NamedValue) (err error) {
	nv.Value, err = converter{}.ConvertValue(nv.Value)
	return
}

// readColumns updates the statement's cached columns when the server sends them.
func (stmt *mysqlStmt) readColumns(count int, metadataFollows bool) error {
	if !metadataFollows {
		return stmt.mc.skipEof()
	}
	columns, err := stmt.mc.readColumns(count, stmt.columns)
	if err == nil {
		stmt.columns = columns
	}
	return err
}

func (stmt *mysqlStmt) Exec(args []driver.Value) (driver.Result, error) {
	result, err := stmt.execOnce(args)
	if err != nil && staleStatementError(err) {
		if reprepareErr := stmt.reprepare(); reprepareErr == nil {
			return stmt.execOnce(args)
		}
	}
	return result, err
}

func (stmt *mysqlStmt) execOnce(args []driver.Value) (driver.Result, error) {
	if stmt.mc == nil || stmt.mc.closed.Load() || stmt.closed {
		return nil, driver.ErrBadConn
	}
	// Send command
	err := stmt.writeExecutePacket(args)
	if err != nil {
		return nil, stmt.mc.markBadConn(err)
	}

	mc := stmt.mc
	handleOk := stmt.mc.clearResult()

	// Read Result
	resLen, metadataFollows, err := handleOk.readResultSetHeaderPacket()
	if err != nil {
		return nil, err
	}

	if resLen > 0 {
		// Columns
		if mc.extCapabilities&clientCacheMetadata != 0 {
			// A subsequent Query may need the cached columns.
			err = stmt.readColumns(resLen, metadataFollows)
		} else {
			err = mc.skipColumns(resLen)
		}
		if err != nil {
			return nil, err
		}

		// Rows
		if err = mc.skipRows(); err != nil {
			return nil, err
		}
	}

	if err := handleOk.discardResults(); err != nil {
		return nil, err
	}

	copied := mc.result
	return &copied, nil
}

func (stmt *mysqlStmt) Query(args []driver.Value) (driver.Rows, error) {
	return stmt.query(args)
}

func (stmt *mysqlStmt) query(args []driver.Value) (*binaryRows, error) {
	rows, err := stmt.queryOnce(args)
	if err != nil && staleStatementError(err) {
		if reprepareErr := stmt.reprepare(); reprepareErr == nil {
			return stmt.queryOnce(args)
		}
	}
	return rows, err
}

func (stmt *mysqlStmt) queryOnce(args []driver.Value) (*binaryRows, error) {
	if stmt.mc == nil || stmt.mc.closed.Load() || stmt.closed {
		return nil, driver.ErrBadConn
	}
	// Send command
	err := stmt.writeExecutePacket(args)
	if err != nil {
		return nil, stmt.mc.markBadConn(err)
	}

	mc := stmt.mc

	// Read Result
	handleOk := stmt.mc.clearResult()
	resLen, metadataFollows, err := handleOk.readResultSetHeaderPacket()
	if err != nil {
		return nil, err
	}

	rows := new(binaryRows)

	if resLen > 0 {
		rows.mc = mc
		if err := stmt.readColumns(resLen, metadataFollows); err != nil {
			return nil, err
		}
		rows.rs.columns = stmt.columns
	} else {
		rows.rs.done = true

		switch err := rows.NextResultSet(); err {
		case nil, io.EOF:
			return rows, nil
		default:
			return nil, err
		}
	}

	return rows, err
}

var jsonType = reflect.TypeFor[json.RawMessage]()

type converter struct{}

// ConvertValue mirrors the reference/default converter in database/sql/driver
// with _one_ exception.  We support uint64 with their high bit and the default
// implementation does not.  This function should be kept in sync with
// database/sql/driver defaultConverter.ConvertValue() except for that
// deliberate difference.
func (c converter) ConvertValue(v any) (driver.Value, error) {
	if driver.IsValue(v) {
		return v, nil
	}

	if vr, ok := v.(driver.Valuer); ok {
		sv, err := callValuerValue(vr)
		if err != nil {
			return nil, err
		}
		if driver.IsValue(sv) {
			return sv, nil
		}
		// A value returned from the Valuer interface can be "a type handled by
		// a database driver's NamedValueChecker interface" so we should accept
		// uint64 here as well.
		if u, ok := sv.(uint64); ok {
			return u, nil
		}
		return nil, fmt.Errorf("non-Value type %T returned from Value", sv)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr:
		// indirect pointers
		if rv.IsNil() {
			return nil, nil
		} else {
			return c.ConvertValue(rv.Elem().Interface())
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return rv.Float(), nil
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.Slice:
		switch t := rv.Type(); {
		case t == jsonType:
			return v, nil
		case t.Elem().Kind() == reflect.Uint8:
			return rv.Bytes(), nil
		default:
			return nil, fmt.Errorf("unsupported type %T, a slice of %s", v, t.Elem().Kind())
		}
	case reflect.String:
		return rv.String(), nil
	}
	return nil, fmt.Errorf("unsupported type %T, a %s", v, rv.Kind())
}

var valuerReflectType = reflect.TypeFor[driver.Valuer]()

// callValuerValue returns vr.Value(), with one exception:
// If vr.Value is an auto-generated method on a pointer type and the
// pointer is nil, it would panic at runtime in the panicwrap
// method. Treat it like nil instead.
//
// This is so people can implement driver.Value on value types and
// still use nil pointers to those types to mean nil/NULL, just like
// string/*string.
//
// This is an exact copy of the same-named unexported function from the
// database/sql package.
func callValuerValue(vr driver.Valuer) (v driver.Value, err error) {
	if rv := reflect.ValueOf(vr); rv.Kind() == reflect.Ptr &&
		rv.IsNil() &&
		rv.Type().Elem().Implements(valuerReflectType) {
		return nil, nil
	}
	return vr.Value()
}

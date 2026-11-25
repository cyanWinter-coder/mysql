// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2013 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// ErrConnClosed is returned when a connection is used after Close. It also
// matches database/sql/driver.ErrBadConn so database/sql can replace it.
var ErrConnClosed error = &ConnClosedError{}

// Various errors the driver might return. Can change between driver versions.
var (
	ErrInvalidConn       = errors.New("invalid connection")
	ErrConnectionClosed  = ErrConnClosed
	ErrAlreadyClosed     = ErrConnClosed
	ErrClosed            = ErrConnClosed
	ErrTimeout           = errors.New("i/o timeout")
	ErrReadTimeout       = errors.New("read timeout")
	ErrWriteTimeout      = errors.New("write timeout")
	ErrConnectTimeout    = errors.New("connect timeout")
	ErrConnectionTimeout = ErrConnectTimeout
	ErrDialTimeout       = ErrConnectTimeout
	ErrTimeoutRead       = ErrReadTimeout
	ErrTimeoutWrite      = ErrWriteTimeout
	ErrTimeoutConnect    = ErrConnectTimeout
	ErrTimeoutDial       = ErrConnectTimeout
	ErrMalformPkt        = errors.New("malformed packet")
	ErrNoTLS             = errors.New("TLS requested but server does not support TLS")
	ErrCleartextPassword = errors.New("this user requires clear text authentication. If you still want to use it, please add 'allowCleartextPasswords=1' to your DSN")
	ErrNativePassword    = errors.New("this user requires mysql native password authentication")
	ErrOldPassword       = errors.New("this user requires old password authentication. If you still want to use it, please add 'allowOldPasswords=1' to your DSN. See also https://github.com/go-sql-driver/mysql/wiki/old_passwords")
	ErrUnknownPlugin     = errors.New("this authentication plugin is not supported")
	ErrOldProtocol       = errors.New("MySQL server does not support required protocol 41+")
	ErrPktSync           = errors.New("commands out of sync. You can't run this command now")
	ErrPktSyncMul        = errors.New("commands out of sync. Did you run multiple statements at once?")
	ErrPktTooLarge       = errors.New("packet for query is too large. Try adjusting the `Config.MaxAllowedPacket`")
	ErrBusyBuffer        = errors.New("busy buffer")

	ErrOpenIDConnectToken        = errors.New("OpenID Connect requires a non-empty token")
	ErrOpenIDConnectTLS          = errors.New("OpenID Connect requires driver-managed TLS")
	ErrOpenIDConnectSwitch       = errors.New("OpenID Connect does not allow authentication switches")
	ErrOpenIDConnectCapabilities = errors.New("OpenID Connect requires plugin authentication and length-encoded authentication data")

	// errBadConnNoWrite is used for connection errors where nothing was sent to the database yet.
	// If this happens first in a function starting a database interaction, it should be replaced by driver.ErrBadConn
	// to trigger a resend. Use mc.markBadConn(err) to do this.
	// See https://github.com/go-sql-driver/mysql/pull/302
	errBadConnNoWrite          = errors.New("bad connection")
	errUnexpectedRead          = errors.New("unexpected read from socket")
	errUnexpectedReadNonSocket = errors.New("unexpected read from non-socket")
)

var defaultLogger = Logger(log.New(os.Stderr, "[mysql] ", log.Ldate|log.Ltime))

// Logger is used to log critical error messages.
type Logger interface {
	Print(v ...any)
}

// NopLogger is a nop implementation of the Logger interface.
type NopLogger struct{}

// Print implements Logger interface.
func (nl *NopLogger) Print(_ ...any) {}

// SetLogger is used to set the default logger for critical errors.
// The initial logger is os.Stderr.
func SetLogger(logger Logger) error {
	if logger == nil {
		return errors.New("logger is nil")
	}
	defaultLogger = logger
	return nil
}

// MySQLError is an error type which represents a single MySQL error
type MySQLError struct {
	Number   uint16
	SQLState [5]byte
	Message  string
}

func (me *MySQLError) Error() string {
	if me.SQLState != [5]byte{} {
		return fmt.Sprintf("Error %d (%s): %s", me.Number, me.SQLState, me.Message)
	}

	return fmt.Sprintf("Error %d: %s", me.Number, me.Message)
}

func (me *MySQLError) Is(err error) bool {
	if merr, ok := err.(*MySQLError); ok {
		return merr.Number == me.Number
	}
	return false
}

// TimeoutError wraps an error caused by a read, write, or connection
// (dial) timeout. It preserves the original error for errors.Is/errors.As and
// implements net.Error so callers can classify timeouts without matching
// error strings.
type TimeoutError struct {
	// Op is one of "read", "write", or "connect".
	Op string

	// Kind is the corresponding ErrReadTimeout, ErrWriteTimeout, or
	// ErrConnectTimeout sentinel.
	Kind error

	// Duration is the configured timeout, when one was set.
	Duration time.Duration

	// Err is the underlying error.
	Err error
}

// Operation-specific aliases make errors.As references readable while all
// timeout errors share the same implementation.
type (
	ReadTimeoutError       = TimeoutError
	WriteTimeoutError      = TimeoutError
	ConnectTimeoutError    = TimeoutError
	ConnectionTimeoutError = TimeoutError
	DialTimeoutError       = TimeoutError
)

func (e *TimeoutError) Error() string {
	msg := "timeout"
	if e.Kind != nil {
		msg = e.Kind.Error()
	}
	if e.Duration > 0 {
		msg += " after " + e.Duration.String()
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *TimeoutError) Unwrap() error {
	return e.Err
}

// Is makes every operation timeout match ErrTimeout and lets errors.Is match
// the operation-specific sentinel stored in Kind.
func (e *TimeoutError) Is(target error) bool {
	return target == ErrTimeout || target == e.Kind
}

func (e *TimeoutError) Timeout() bool {
	return true
}

func (e *TimeoutError) Temporary() bool {
	var netErr net.Error
	if errors.As(e.Err, &netErr) {
		return netErr.Temporary()
	}
	return false
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func wrapTimeout(kind error, op string, duration time.Duration, err error) error {
	if err == nil || !isTimeoutError(err) {
		return err
	}
	return &TimeoutError{
		Op:       op,
		Kind:     kind,
		Duration: duration,
		Err:      err,
	}
}

func wrapReadTimeout(err error, duration time.Duration) error {
	return wrapTimeout(ErrReadTimeout, "read", duration, err)
}

func wrapWriteTimeout(err error, duration time.Duration) error {
	return wrapTimeout(ErrWriteTimeout, "write", duration, err)
}

func wrapConnectTimeout(err error, duration time.Duration) error {
	if err == nil || !isTimeoutError(err) {
		return err
	}

	// Preserve the concrete *net.OpError returned by net.Dial and its error
	// text. Enrich its wrapped cause so errors.Is can also match the
	// driver's connect-timeout sentinel.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil && !errors.Is(opErr.Err, ErrConnectTimeout) {
		opErr.Err = &classifiedTimeoutCause{
			kind:     ErrConnectTimeout,
			op:       "connect",
			duration: duration,
			err:      opErr.Err,
		}
		return err
	}

	return &TimeoutError{
		Op:       "connect",
		Kind:     ErrConnectTimeout,
		Duration: duration,
		Err:      err,
	}
}

// classifiedTimeoutCause attaches an operation sentinel to an existing error
// without changing its Error text. This lets standard net.OpError values keep
// their concrete type and message while becoming errors.Is-compatible with
// the driver's timeout categories.
type classifiedTimeoutCause struct {
	kind     error
	op       string
	duration time.Duration
	err      error
}

func (e *classifiedTimeoutCause) Error() string {
	return e.err.Error()
}

func (e *classifiedTimeoutCause) Unwrap() error {
	return e.err
}

func (e *classifiedTimeoutCause) Is(target error) bool {
	return target == ErrTimeout || target == e.kind
}

func (e *classifiedTimeoutCause) Timeout() bool {
	return true
}

func (e *classifiedTimeoutCause) Temporary() bool {
	var netErr net.Error
	if errors.As(e.err, &netErr) {
		return netErr.Temporary()
	}
	return false
}

// ConnClosedError gives direct driver callers an explicit closed-connection
// error while remaining retryable through database/sql. When closure was
// caused by context cancellation, Cause preserves that error in Unwrap.
type ConnClosedError struct {
	Cause error
}

// ConnectionClosedError is an alternate name for ConnClosedError.
type ConnectionClosedError = ConnClosedError

func (e *ConnClosedError) Error() string {
	if e.Cause != nil {
		return "connection is already closed: " + e.Cause.Error()
	}
	return "connection is already closed"
}

func (e *ConnClosedError) Unwrap() error {
	return e.Cause
}

func (*ConnClosedError) Is(target error) bool {
	return target == ErrConnClosed ||
		target == ErrConnectionClosed ||
		target == ErrAlreadyClosed ||
		target == ErrClosed ||
		target == ErrInvalidConn ||
		target == driver.ErrBadConn ||
		target == sql.ErrConnDone ||
		target == net.ErrClosed
}

func (mc *mysqlConn) closedConnectionError() error {
	if err := mc.canceled.Value(); err != nil {
		return &ConnClosedError{Cause: err}
	}
	return ErrConnClosed
}

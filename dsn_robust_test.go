// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// recordingLogger captures driver log output for assertion.
type recordingLogger struct {
	messages []string
}

func (l *recordingLogger) Print(v ...any) {
	l.messages = append(l.messages, fmt.Sprint(v...))
}

func (l *recordingLogger) contains(substr string) bool {
	for _, msg := range l.messages {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// withRecordingLogger swaps the package default logger for the duration of
// the test and returns the recorder.
func withRecordingLogger(t *testing.T) *recordingLogger {
	t.Helper()
	rec := &recordingLogger{}
	old := defaultLogger
	defaultLogger = rec
	t.Cleanup(func() { defaultLogger = old })
	return rec
}

func TestParseDSNUnknownParamsWarnNotFail(t *testing.T) {
	rec := withRecordingLogger(t)

	// Historical/foreign parameters must not break parsing: they are kept as
	// connection parameters (system variables).
	dsn := "user:pass@tcp(127.0.0.1:3306)/db?legacyOption=1&autocommit=1&timout=500ms"
	cfg, err := ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN() returned error for unknown params: %v", err)
	}
	if got := cfg.Params["timout"]; got != "500ms" {
		t.Fatalf("Params[timout] = %q; want %q", got, "500ms")
	}
	if got := cfg.Params["legacyOption"]; got != "1" {
		t.Fatalf("Params[legacyOption] = %q; want %q", got, "1")
	}
	if got := cfg.Params["autocommit"]; got != "1" {
		t.Fatalf("Params[autocommit] = %q; want %q", got, "1")
	}

	// Ordinary system variables must not produce warnings...
	if rec.contains("autocommit") {
		t.Errorf("ordinary system variable produced a warning: %v", rec.messages)
	}
	// ...but a name close to a known driver parameter should hint at it.
	if !rec.contains("did you mean timeout?") {
		t.Errorf("no misspelling hint logged: %v", rec.messages)
	}

	// Unknown parameters still round-trip through FormatDSN.
	reformatted := cfg.FormatDSN()
	cfg2, err := ParseDSN(reformatted)
	if err != nil {
		t.Fatalf("round-trip ParseDSN(%q) failed: %v", reformatted, err)
	}
	if cfg2.Params["legacyOption"] != "1" || cfg2.Params["autocommit"] != "1" {
		t.Fatalf("round-trip lost unknown params: %#v", cfg2.Params)
	}
}

func TestParseDSNMalformedEscapeInUnknownParam(t *testing.T) {
	rec := withRecordingLogger(t)

	// A bad percent-escape in an unknown parameter value must not fail the
	// whole parse; the raw value is retained and a warning is emitted.
	cfg, err := ParseDSN("/db?legacy=a%2")
	if err != nil {
		t.Fatalf("ParseDSN() failed on malformed escape: %v", err)
	}
	if got := cfg.Params["legacy"]; got != "a%2" {
		t.Fatalf("Params[legacy] = %q; want raw %q", got, "a%2")
	}
	if !rec.contains("invalid URL escape") {
		t.Errorf("no warning for malformed escape: %v", rec.messages)
	}
}

func TestParseDSNPasswordSpecialCharsRoundTrip(t *testing.T) {
	passwords := []string{
		"p@ss(word)",
		"100%",          // bare percent without valid escape
		"a+b",           // plus must survive (no query-form decoding)
		"a/b:c@d?e&f=g", // full set of DSN metacharacters in the value part
		"a b",
		`a'b"c`,
		"密码#1!",
		"plain",
	}

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			cfg := NewConfig()
			cfg.User = "user"
			cfg.Passwd = password
			cfg.Net = "tcp"
			cfg.Addr = "127.0.0.1:3306"
			cfg.DBName = "db"

			dsn := cfg.FormatDSN()
			parsed, err := ParseDSN(dsn)
			if err != nil {
				t.Fatalf("ParseDSN(%q) failed: %v", dsn, err)
			}
			if parsed.Passwd != password {
				t.Fatalf("password round-trip: got %q, want %q (dsn=%q)", parsed.Passwd, password, dsn)
			}
			if got := parsed.FormatDSN(); got != dsn {
				t.Fatalf("FormatDSN not idempotent:\n got %q\nwant %q", got, dsn)
			}
		})
	}
}

func TestParseDSNEscapedAndRawPasswords(t *testing.T) {
	// Percent-encoded credentials are decoded.
	cfg, err := ParseDSN("user:p%40ss%28word%29@tcp(127.0.0.1:3306)/db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != "p@ss(word)" {
		t.Fatalf("escaped password decoded as %q", cfg.Passwd)
	}

	// A raw password containing '%' that is not a valid escape stays intact
	// for backwards compatibility with unescaped DSNs.
	cfg, err = ParseDSN("user:100%@tcp(127.0.0.1:3306)/db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != "100%" {
		t.Fatalf("raw percent password = %q; want %q", cfg.Passwd, "100%")
	}

	// Escaped username is decoded as well.
	cfg, err = ParseDSN("us%40er:pass@tcp(127.0.0.1:3306)/db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "us@er" {
		t.Fatalf("escaped user decoded as %q", cfg.User)
	}
}

func TestParseDSNUserinfoStructuralCharsRoundTrip(t *testing.T) {
	// ':' in the username and every structural character in the password
	// must survive a FormatDSN -> ParseDSN round trip.
	cases := []struct {
		user   string
		passwd string
	}{
		{"us:er", "pw"},
		{"us:er@host", "p:ss@/()?&=%"},
		{"user", "p/ss?&= #%()"},
		{"u@h", "a+b,c;d"},
	}
	for _, tc := range cases {
		cfg := NewConfig()
		cfg.User = tc.user
		cfg.Passwd = tc.passwd
		cfg.Net = "tcp"
		cfg.Addr = "127.0.0.1:3306"

		dsn := cfg.FormatDSN()
		parsed, err := ParseDSN(dsn)
		if err != nil {
			t.Fatalf("ParseDSN(%q) failed: %v", dsn, err)
		}
		if parsed.User != tc.user {
			t.Errorf("user round-trip: got %q, want %q (dsn=%q)", parsed.User, tc.user, dsn)
		}
		if parsed.Passwd != tc.passwd {
			t.Errorf("password round-trip: got %q, want %q (dsn=%q)", parsed.Passwd, tc.passwd, dsn)
		}
		if reparsed := parsed.FormatDSN(); reparsed != dsn {
			t.Errorf("FormatDSN not idempotent:\n got %q\nwant %q", reparsed, dsn)
		}
	}
}

func TestParseDSNTypedErrorsNameField(t *testing.T) {
	tests := []struct {
		dsn     string
		field   string
		wantSub string
	}{
		{"/?timeout=abc", "timeout", "invalid timeout value"},
		{"/?readTimeout=1lightyear", "readTimeout", "invalid readTimeout value"},
		{"/?writeTimeout=x", "writeTimeout", "invalid writeTimeout value"},
		{"/?timeTruncate=x", "timeTruncate", "invalid timeTruncate value"},
		{"/?parseTime=maybe", "parseTime", "invalid parseTime value"},
		{"/?allowAllFiles=yes", "allowAllFiles", "invalid allowAllFiles value"},
		{"/?compress=banana", "compress", "invalid compress value"},
		{"/?maxAllowedPacket=big", "maxAllowedPacket", "invalid maxAllowedPacket value"},
		{"/?charset=utf8,,utf8mb4", "charset", "empty charset at position 2"},
		{"/?charset=", "charset", "empty charset at position 1"},
		{"/?loc=No%2FSuch%2FPlace_123", "loc", "invalid loc value"},
	}

	for _, tt := range tests {
		t.Run(tt.dsn, func(t *testing.T) {
			cfg, err := ParseDSN(tt.dsn)
			if err == nil {
				t.Fatal("ParseDSN() expected error, got nil")
			}
			if cfg != nil {
				t.Fatalf("ParseDSN() returned non-nil config on error: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Errorf("error %q does not name field %q", err, tt.field)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestParseDSNFailureReturnsNilConfig(t *testing.T) {
	invalidDSNs := []string{
		"@net(addr/",
		"@tcp(/",
		"tcp(/",
		"(/",
		"net(addr)//",
		"User:pass@tcp(1.2.3.4:3306)",
		"net()/",
		"user:pass@tcp(127.0.0.1:3306)/db/name",
		"/?timeout=not-a-duration",
		"/?parseTime=xxx",
		"/?charset=utf8,,latin1",
		"/?maxAllowedPacket=nope",
		// Failures surfaced from normalize() must also discard the config.
		"net()/",
		"/?tls=no_such_registered_tls_config",
		"/?serverPubKey=no_such_registered_key",
	}
	for _, dsn := range invalidDSNs {
		cfg, err := ParseDSN(dsn)
		if err == nil {
			t.Errorf("ParseDSN(%q): expected error, got nil", dsn)
			continue
		}
		if cfg != nil {
			t.Errorf("ParseDSN(%q): returned half-initialized config %#v with error %v", dsn, cfg, err)
		}
	}
}

func TestParseDSNSubMillisecondDuration(t *testing.T) {
	// The migration regression: short durations such as 500ms are valid.
	cfg, err := ParseDSN("/?timeout=500ms&readTimeout=250us&writeTimeout=1h2m3s")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 500*time.Millisecond {
		t.Errorf("Timeout = %v; want 500ms", cfg.Timeout)
	}
	if cfg.ReadTimeout != 250*time.Microsecond {
		t.Errorf("ReadTimeout = %v; want 250us", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != time.Hour+2*time.Minute+3*time.Second {
		t.Errorf("WriteTimeout = %v", cfg.WriteTimeout)
	}
}

func TestParseDSNCharsetValidation(t *testing.T) {
	cfg, err := ParseDSN("/?charset=utf8mb4,utf8")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.charsets, ","); got != "utf8mb4,utf8" {
		t.Fatalf("charsets = %v", cfg.charsets)
	}

	for _, bad := range []string{
		"/?charset=,utf8",
		"/?charset=utf8,",
		"/?charset=utf8,,latin1",
		"/?charset= ,utf8",
	} {
		if _, err := ParseDSN(bad); err == nil {
			t.Errorf("ParseDSN(%q) expected error", bad)
		}
	}
}

func TestSuggestDSNParam(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"timout", "timeout"},             // missing letter
		{"timeoutx", "timeout"},           // extra letter
		{"timeoat", "timeout"},            // substituted letter
		{"allowallfile", "allowAllFiles"}, // missing trailing 's'
		{"parsetim", "parseTime"},         // missing final letter, case-insensitive
		// Ordinary system variables and names more than one edit away produce
		// no suggestion.
		{"autocommit", ""},
		{"transaction_isolation", ""},
		{"aurora_read_replica_read_committed", ""},
		{"readtimezz", ""}, // two substituted positions
		{"x", ""},
	}
	for _, tt := range tests {
		if got := suggestDSNParam(tt.key); got != tt.want {
			t.Errorf("suggestDSNParam(%q) = %q; want %q", tt.key, got, tt.want)
		}
	}
}

func TestOneEditHelpers(t *testing.T) {
	if !oneEditAway("abc", "axc") {
		t.Error("substitution not detected")
	}
	if !oneEditAway("abc", "acb") {
		t.Error("adjacent transposition not detected")
	}
	if oneEditAway("abc", "abc") {
		t.Error("identical strings reported as one edit")
	}
	if oneEditAway("abc", "axy") {
		t.Error("two substitutions reported as one edit")
	}
	if oneEditAway("abc", "xyz") {
		t.Error("three substitutions reported as one edit")
	}
	if !oneInsertionAway("abc", "abxc") {
		t.Error("single insertion not detected")
	}
	if oneInsertionAway("abc", "xxabc") {
		t.Error("two insertions reported as one")
	}
	if !oneInsertionAway("abc", "abcd") {
		t.Error("appended character not detected")
	}
}

func TestFormatDSNEscapesSpecialChars(t *testing.T) {
	cfg := NewConfig()
	cfg.User = "user@host"
	cfg.Passwd = "p/ss?&= #%"
	cfg.Net = "tcp"
	cfg.Addr = "127.0.0.1:3306"

	dsn := cfg.FormatDSN()
	// Metacharacters must be percent-encoded so reparsing yields the same
	// fields instead of splitting on them.
	for _, ch := range []string{"/", "?", "&", "=", " "} {
		if strings.Contains(strings.SplitN(dsn, "@", 2)[0], ch) {
			t.Errorf("userinfo in %q contains unescaped %q", dsn, ch)
		}
	}
	parsed, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User != cfg.User || parsed.Passwd != cfg.Passwd {
		t.Fatalf("round-trip mismatch: user=%q passwd=%q", parsed.User, parsed.Passwd)
	}
}

func TestParseDSNQuerySpecialCharsInParamsRoundTrip(t *testing.T) {
	// Parameters with query metacharacters use standard QueryEscape and must
	// round-trip exactly.
	original := NewConfig()
	original.DBName = "db"
	if err := original.Apply(AddParam("sysvar", "a&b=c?d %e")); err != nil {
		t.Fatal(err)
	}
	dsn := original.FormatDSN()
	if !strings.Contains(dsn, url.QueryEscape("a&b=c?d %e")) {
		t.Fatalf("FormatDSN() = %q; value not query-escaped", dsn)
	}
	parsed, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Params["sysvar"]; got != "a&b=c?d %e" {
		t.Fatalf("param round-trip = %q", got)
	}
}

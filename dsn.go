// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2016 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	errInvalidDSNUnescaped = errors.New("invalid DSN: did you forget to escape a param value?")
	errInvalidDSNAddr      = errors.New("invalid DSN: network address not terminated (missing closing brace)")
	errInvalidDSNNoSlash   = errors.New("invalid DSN: missing the slash separating the database name")
	errUnsafeCharset       = errors.New("interpolateParams cannot be used with unsafe charsets")
)

// knownDSNParams is the set of DSN parameter names the driver understands.
// It is used to recognize likely misspellings of driver parameters among the
// unknown parameters, which are otherwise treated as system variables (see
// Config.Params).
var knownDSNParams = map[string]struct{}{
	"allowAllFiles":            {},
	"allowCleartextPasswords":  {},
	"allowFallbackToPlaintext": {},
	"allowNativePasswords":     {},
	"allowOldPasswords":        {},
	"checkConnLiveness":        {},
	"charset":                  {},
	"clientFoundRows":          {},
	"collation":                {},
	"columnsWithAlias":         {},
	"compress":                 {},
	"connectionAttributes":     {},
	"interpolateParams":        {},
	"loc":                      {},
	"maxAllowedPacket":         {},
	"multiStatements":          {},
	"parseTime":                {},
	"readTimeout":              {},
	"rejectReadOnly":           {},
	"serverPubKey":             {},
	"strict":                   {},
	"timeout":                  {},
	"timeTruncate":             {},
	"tinyInt1IsBool":           {},
	"tls":                      {},
	"writeTimeout":             {},
}

// knownDSNParamNamesLower holds the lowercase form of each entry in
// knownDSNParams, prepared once so suggestDSNParam does not allocate while
// scanning candidates.
var knownDSNParamNamesLower = func() []string {
	names := make([]string, 0, len(knownDSNParams))
	for name := range knownDSNParams {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	return names
}()

// canonicalDSNParamName maps a lowercase parameter name back to its
// canonical spelling for warning messages.
var canonicalDSNParamName = func() map[string]string {
	names := make(map[string]string, len(knownDSNParams))
	for name := range knownDSNParams {
		names[strings.ToLower(name)] = name
	}
	return names
}()

// maxDSNParamSuggestionLen is the longest parameter name for which a
// misspelling suggestion is attempted; longer names are treated as ordinary
// system variables. Driver parameter names are far shorter.
const maxDSNParamSuggestionLen = 128

// oneEditAway reports whether two equal-length strings are a single
// substitution or a single adjacent transposition apart.
func oneEditAway(a, b string) bool {
	first := -1
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		if first < 0 {
			first = i
			continue
		}
		// A second difference is only acceptable as the other half of an
		// adjacent transposition; everything else is at least two edits.
		return i == first+1 && a[first] == b[i] && a[i] == b[first] &&
			// no further differences after the swapped pair
			a[i+1:] == b[i+1:]
	}
	return first >= 0
}

// oneInsertionAway reports whether longer is one insertion away from shorter,
// i.e. shorter is longer with a single character removed (and vice versa).
func oneInsertionAway(shorter, longer string) bool {
	i, j := 0, 0
	for i < len(shorter) && j < len(longer) {
		if shorter[i] == longer[j] {
			i++
			j++
			continue
		}
		j++
		if j-i > 1 {
			return false
		}
	}
	return true
}

// suggestDSNParam returns the canonical name of a known driver parameter the
// given key is one edit away from (a likely typo), or "" otherwise. Ordinary
// system variables such as "autocommit" produce no suggestion, so the common
// DSN path stays cheap.
func suggestDSNParam(key string) string {
	if key == "" || len(key) > maxDSNParamSuggestionLen {
		return ""
	}
	lowerKey := strings.ToLower(key)
	for _, known := range knownDSNParamNamesLower {
		switch len(known) - len(lowerKey) {
		case 0:
			// Substitution, transposition, or identical (an identical name
			// cannot reach this function: known keys are handled by the
			// switch in parseDSNParams).
			if lowerKey != known && oneEditAway(lowerKey, known) {
				return canonicalDSNParamName[known]
			}
		case 1:
			if oneInsertionAway(lowerKey, known) {
				return canonicalDSNParamName[known]
			}
		case -1:
			if oneInsertionAway(known, lowerKey) {
				return canonicalDSNParamName[known]
			}
		}
	}
	return ""
}

// Config is a configuration parsed from a DSN string.
// If a new Config is created instead of being parsed from a DSN string,
// the NewConfig function should be used, which sets default values.
type Config struct {
	// non boolean fields

	User                 string            // Username
	Passwd               string            // Password (requires User)
	Net                  string            // Network (e.g. "tcp", "tcp6", "unix". default: "tcp")
	Addr                 string            // Address (default: "127.0.0.1:3306" for "tcp" and "/tmp/mysql.sock" for "unix")
	DBName               string            // Database name
	Params               map[string]string // Connection parameters. Use Apply(AddParam(...)) to preserve insertion order.
	ConnectionAttributes string            // Connection Attributes, comma-delimited string of user-defined "key:value" pairs
	Collation            string            // Connection collation. When set, this will be set in SET NAMES <charset> COLLATE <collation> query
	Loc                  *time.Location    // Location for time.Time values
	MaxAllowedPacket     int               // Max packet size allowed
	ServerPubKey         string            // Server public key name
	TLSConfig            string            // TLS configuration name
	TLS                  *tls.Config       // TLS configuration, its priority is higher than TLSConfig
	Timeout              time.Duration     // Dial timeout
	ReadTimeout          time.Duration     // I/O read timeout
	WriteTimeout         time.Duration     // I/O write timeout
	Logger               Logger            // Logger
	// DialFunc specifies the dial function for creating connections
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

	// boolean fields

	AllowAllFiles            bool // Allow all files to be used with LOAD DATA LOCAL INFILE
	AllowCleartextPasswords  bool // Allows the cleartext client side plugin
	AllowFallbackToPlaintext bool // Allows fallback to unencrypted connection if server does not support TLS
	AllowNativePasswords     bool // Allows the native password authentication method
	AllowOldPasswords        bool // Allows the old insecure password method
	CheckConnLiveness        bool // Check connections for liveness before using them
	ClientFoundRows          bool // Return number of matching rows instead of rows changed
	ColumnsWithAlias         bool // Prepend table alias to column names
	InterpolateParams        bool // Interpolate placeholders into query string
	MultiStatements          bool // Allow multiple statements in one query
	ParseTime                bool // Parse time values to time.Time
	RejectReadOnly           bool // Reject read-only connections

	// unexported fields. new options should be come here.
	// boolean first. alphabetical order.

	compress       bool // Enable compression
	tinyInt1IsBool bool // Treat signed TINYINT(1) as boolean

	beforeConnect     func(context.Context, *Config) error // Invoked before a connection is established
	encodedAttributes string                               // Encoded connection attributes
	openIDToken       string                               // OpenID Connect token; never included in the DSN
	paramOrder        []string                             // Order of connection parameters parsed from the DSN
	pubKey            *rsa.PublicKey                       // Server public key
	timeTruncate      time.Duration                        // Truncate time.Time values to the specified duration
	charsets          []string                             // Connection charset. When set, this will be set in SET NAMES <charset> query
}

// Functional Options Pattern
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
type Option func(*Config) error

// NewConfig creates a new Config and sets default values.
func NewConfig() *Config {
	cfg := &Config{
		Loc:                  time.UTC,
		MaxAllowedPacket:     defaultMaxAllowedPacket,
		Logger:               defaultLogger,
		AllowNativePasswords: true,
		CheckConnLiveness:    true,
	}
	return cfg
}

// Apply applies the given options to the Config object.
func (c *Config) Apply(opts ...Option) error {
	for _, opt := range opts {
		err := opt(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddParam adds a connection parameter.
//
// Parameters added with AddParam retain their order in [Config.FormatDSN] and
// are applied to the connection in that order. If name already exists, it is
// moved to the end of the parameter order.
func AddParam(name, value string) Option {
	return func(cfg *Config) error {
		params := cfg.orderedParams()
		if i := slices.Index(params, name); i >= 0 {
			params = slices.Delete(params, i, i+1)
		}

		if cfg.Params == nil {
			cfg.Params = make(map[string]string)
		}
		cfg.Params[name] = value
		cfg.paramOrder = append(params, name)
		return nil
	}
}

// TimeTruncate sets the time duration to truncate time.Time values in
// query parameters.
func TimeTruncate(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.timeTruncate = d
		return nil
	}
}

// OIDCToken sets the JWT for OpenID Connect authentication.
// Empty tokens return ErrOpenIDConnectToken without changing the configuration.
// Use [BeforeConnect] to refresh the token with cfg.Apply(OIDCToken(token)).
// The token is omitted from [Config.FormatDSN]. OIDC requires driver-managed TLS
// with application-configured server verification and rejects authentication switches.
func OIDCToken(token string) Option {
	return func(cfg *Config) error {
		if token == "" {
			return ErrOpenIDConnectToken
		}
		cfg.openIDToken = token
		return nil
	}
}

// BeforeConnect sets the function to be invoked before a connection is established.
// If the function changes [Config.Addr] while [Config.TLS] is non-nil and its
// InsecureSkipVerify field is false, it must also update ServerName to match
// the hostname in the new address.
func BeforeConnect(fn func(context.Context, *Config) error) Option {
	return func(cfg *Config) error {
		cfg.beforeConnect = fn
		return nil
	}
}

// EnableCompression enables compression. Import mysql/zstd to prefer zstd when
// supported by the server; otherwise connections use zlib when supported.
func EnableCompression(yes bool) Option {
	return func(cfg *Config) error {
		cfg.compress = yes
		return nil
	}
}

// TinyInt1IsBool controls whether signed TINYINT(1) columns are treated as boolean.
// It is disabled by default.
func TinyInt1IsBool(yes bool) Option {
	return func(cfg *Config) error {
		cfg.tinyInt1IsBool = yes
		return nil
	}
}

// Charset sets the connection charset and collation.
//
// charset is the connection charset.
// collation is the connection collation. It can be null or empty string.
//
// When collation is not specified, `SET NAMES <charset>` command is sent when the connection is established.
// When collation is specified, `SET NAMES <charset> COLLATE <collation>` command is sent when the connection is established.
func Charset(charset, collation string) Option {
	return func(cfg *Config) error {
		cfg.charsets = []string{charset}
		cfg.Collation = collation
		return nil
	}
}

func (cfg *Config) Clone() *Config {
	cp := *cfg
	if cp.TLS != nil {
		cp.TLS = cfg.TLS.Clone()
	}
	if cp.Params != nil {
		cp.Params = make(map[string]string, len(cfg.Params))
		maps.Copy(cp.Params, cfg.Params)
	}
	cp.paramOrder = slices.Clone(cfg.paramOrder)
	if cfg.pubKey != nil {
		cp.pubKey = &rsa.PublicKey{
			N: new(big.Int).Set(cfg.pubKey.N),
			E: cfg.pubKey.E,
		}
	}
	return &cp
}

// checkUnsafeCharset returns an error if interpolateParams is used with a
// charset that is unsafe for backslash escaping.
func (cfg *Config) checkUnsafeCharset() error {
	if !cfg.InterpolateParams {
		return nil
	}
	if cfg.Collation != "" && isUnsafeCollation(cfg.Collation) {
		return errUnsafeCharset
	}
	// Every charset is checked, not only the first, because the fallbacks
	// are used when the preceding ones fail.
	for _, cs := range cfg.charsets {
		if isUnsafeCharset(cs) {
			return errUnsafeCharset
		}
	}
	return nil
}

func (cfg *Config) normalize() error {
	if err := cfg.checkUnsafeCharset(); err != nil {
		return err
	}

	// Set default network if empty
	if cfg.Net == "" {
		cfg.Net = "tcp"
	}

	// Set default address if empty
	if cfg.Addr == "" {
		switch cfg.Net {
		case "tcp":
			cfg.Addr = "127.0.0.1:3306"
		case "unix":
			cfg.Addr = "/tmp/mysql.sock"
		default:
			return errors.New("default addr for network '" + cfg.Net + "' unknown")
		}
	} else if cfg.Net == "tcp" {
		cfg.Addr = ensureHavePort(cfg.Addr)
	}

	if cfg.TLS == nil {
		switch cfg.TLSConfig {
		case "false", "":
			// don't set anything
		case "true":
			cfg.TLS = &tls.Config{}
		case "skip-verify":
			cfg.TLS = &tls.Config{InsecureSkipVerify: true}
		case "preferred":
			cfg.TLS = &tls.Config{InsecureSkipVerify: true}
			cfg.AllowFallbackToPlaintext = true
		default:
			cfg.TLS = getTLSConfigClone(cfg.TLSConfig)
			if cfg.TLS == nil {
				return errors.New("invalid value / unknown config name: " + cfg.TLSConfig)
			}
		}
	}

	if cfg.TLS != nil && cfg.TLS.ServerName == "" && !cfg.TLS.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err == nil {
			cfg.TLS.ServerName = host
		}
	}

	if cfg.ServerPubKey != "" {
		cfg.pubKey = getServerPubKey(cfg.ServerPubKey)
		if cfg.pubKey == nil {
			return errors.New("invalid value / unknown server pub key name: " + cfg.ServerPubKey)
		}
	}

	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}
	cfg.encodedAttributes = encodeConnectionAttributes(cfg)

	return nil
}

func writeDSNParam(buf *bytes.Buffer, hasParam *bool, name, value string) {
	buf.Grow(1 + len(name) + 1 + len(value))
	if !*hasParam {
		*hasParam = true
		buf.WriteByte('?')
	} else {
		buf.WriteByte('&')
	}
	buf.WriteString(name)
	buf.WriteByte('=')
	buf.WriteString(value)
}

// FormatDSN formats the given Config into a DSN string which can be passed to
// the driver.
//
// Note: use [NewConnector] and [database/sql.OpenDB] to open a connection from a [*Config].
func (cfg *Config) FormatDSN() string {
	var buf bytes.Buffer

	// [username[:password]@]
	if len(cfg.User) > 0 {
		buf.WriteString(escapeUserinfo(cfg.User))
		if len(cfg.Passwd) > 0 {
			buf.WriteByte(':')
			buf.WriteString(escapeUserinfo(cfg.Passwd))
		}
		buf.WriteByte('@')
	}

	// [protocol[(address)]]
	if len(cfg.Addr) > 0 {
		net := cfg.Net
		if net == "" {
			net = "tcp"
		}
		buf.WriteString(net)
		buf.WriteByte('(')
		buf.WriteString(cfg.Addr)
		buf.WriteByte(')')
	} else if cfg.Net != "" && cfg.Net != "tcp" {
		// Preserve an explicit non-default protocol when there's no
		// address, so e.g. Net="unix" still round-trips.
		buf.WriteString(cfg.Net)
	}

	// /dbname
	buf.WriteByte('/')
	buf.WriteString(url.PathEscape(cfg.DBName))

	// [?param1=value1&...&paramN=valueN]
	hasParam := false

	if cfg.AllowAllFiles {
		hasParam = true
		buf.WriteString("?allowAllFiles=true")
	}

	if cfg.AllowCleartextPasswords {
		writeDSNParam(&buf, &hasParam, "allowCleartextPasswords", "true")
	}

	if cfg.AllowFallbackToPlaintext {
		writeDSNParam(&buf, &hasParam, "allowFallbackToPlaintext", "true")
	}

	if !cfg.AllowNativePasswords {
		writeDSNParam(&buf, &hasParam, "allowNativePasswords", "false")
	}

	if cfg.AllowOldPasswords {
		writeDSNParam(&buf, &hasParam, "allowOldPasswords", "true")
	}

	if !cfg.CheckConnLiveness {
		writeDSNParam(&buf, &hasParam, "checkConnLiveness", "false")
	}

	if cfg.ClientFoundRows {
		writeDSNParam(&buf, &hasParam, "clientFoundRows", "true")
	}

	if charsets := cfg.charsets; len(charsets) > 0 {
		writeDSNParam(&buf, &hasParam, "charset", strings.Join(charsets, ","))
	}

	if col := cfg.Collation; col != "" {
		writeDSNParam(&buf, &hasParam, "collation", col)
	}

	if cfg.ColumnsWithAlias {
		writeDSNParam(&buf, &hasParam, "columnsWithAlias", "true")
	}

	if cfg.ConnectionAttributes != "" {
		writeDSNParam(&buf, &hasParam, "connectionAttributes", url.QueryEscape(cfg.ConnectionAttributes))
	}

	if cfg.compress {
		writeDSNParam(&buf, &hasParam, "compress", "true")
	}

	if cfg.InterpolateParams {
		writeDSNParam(&buf, &hasParam, "interpolateParams", "true")
	}

	if cfg.Loc != time.UTC && cfg.Loc != nil {
		writeDSNParam(&buf, &hasParam, "loc", url.QueryEscape(cfg.Loc.String()))
	}

	if cfg.MultiStatements {
		writeDSNParam(&buf, &hasParam, "multiStatements", "true")
	}

	if cfg.ParseTime {
		writeDSNParam(&buf, &hasParam, "parseTime", "true")
	}

	if cfg.timeTruncate > 0 {
		writeDSNParam(&buf, &hasParam, "timeTruncate", cfg.timeTruncate.String())
	}

	if cfg.tinyInt1IsBool {
		writeDSNParam(&buf, &hasParam, "tinyInt1IsBool", "true")
	}

	if cfg.ReadTimeout > 0 {
		writeDSNParam(&buf, &hasParam, "readTimeout", cfg.ReadTimeout.String())
	}

	if cfg.RejectReadOnly {
		writeDSNParam(&buf, &hasParam, "rejectReadOnly", "true")
	}

	if len(cfg.ServerPubKey) > 0 {
		writeDSNParam(&buf, &hasParam, "serverPubKey", url.QueryEscape(cfg.ServerPubKey))
	}

	if cfg.Timeout > 0 {
		writeDSNParam(&buf, &hasParam, "timeout", cfg.Timeout.String())
	}

	if len(cfg.TLSConfig) > 0 {
		writeDSNParam(&buf, &hasParam, "tls", url.QueryEscape(cfg.TLSConfig))
	}

	if cfg.WriteTimeout > 0 {
		writeDSNParam(&buf, &hasParam, "writeTimeout", cfg.WriteTimeout.String())
	}

	if cfg.MaxAllowedPacket != defaultMaxAllowedPacket {
		writeDSNParam(&buf, &hasParam, "maxAllowedPacket", strconv.Itoa(cfg.MaxAllowedPacket))
	}

	// other params
	for _, param := range cfg.orderedParams() {
		writeDSNParam(&buf, &hasParam, param, url.QueryEscape(cfg.Params[param]))
	}

	return buf.String()
}

// orderedParams returns connection parameter names in their recorded order,
// followed by any names added directly to Config.Params in sorted order.
func (cfg *Config) orderedParams() []string {
	params := make([]string, 0, len(cfg.Params))
	seen := make(map[string]struct{}, len(cfg.Params))
	for _, param := range cfg.paramOrder {
		if _, ok := cfg.Params[param]; !ok {
			continue
		}
		if _, ok := seen[param]; ok {
			continue
		}
		params = append(params, param)
		seen[param] = struct{}{}
	}

	unordered := make([]string, 0, len(cfg.Params)-len(params))
	for param := range cfg.Params {
		if _, ok := seen[param]; !ok {
			unordered = append(unordered, param)
		}
	}
	sort.Strings(unordered)
	return append(params, unordered...)
}

// unescapeUserinfo percent-decodes the user/password section of a DSN.
//
// The section historically carried no escaping rules, so a value without
// valid percent-escapes is returned unchanged instead of failing: plain
// passwords containing '%' (e.g. "100%") must keep working.
func unescapeUserinfo(value string) string {
	if !strings.ContainsRune(value, '%') {
		return value
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}

// shouldEscapeUserinfo reports whether the byte must be percent-encoded in
// the userinfo section of a DSN: the structural characters ('@', ':', '/',
// '(', ')', '?', '&', '=', '%'), whitespace, non-printables and non-ASCII.
func shouldEscapeUserinfo(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return false
	case c == '-' || c == '_' || c == '.' || c == '~' || c == '!' ||
		c == '$' || c == '\'' || c == '(' || c == ')' || c == '*' ||
		c == '+' || c == ',' || c == ';':
		// Unreserved and sub-delim characters that carry no structural
		// meaning in the userinfo section.
		return false
	default:
		return true
	}
}

// escapeUserinfo percent-encodes every structural or non-ASCII character in
// the DSN userinfo section so that credentials round-trip through
// ParseDSN/FormatDSN. Unreserved ASCII characters are kept verbatim.
func escapeUserinfo(value string) string {
	// Fast path: the common credential consists solely of unreserved bytes,
	// so avoid allocating a builder.
	needsEscape := false
	for i := 0; i < len(value); i++ {
		if shouldEscapeUserinfo(value[i]) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return value
	}

	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !shouldEscapeUserinfo(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte("0123456789ABCDEF"[c>>4])
		b.WriteByte("0123456789ABCDEF"[c&15])
	}
	return b.String()
}

// ParseDSN parses the DSN string to a Config.
// It never returns a partially initialized Config: on any error the
// returned Config is nil.
func ParseDSN(dsn string) (cfg *Config, err error) {
	// New config with some default values. On every error path below this
	// config is discarded and nil is returned, so callers can never observe
	// a half-initialized configuration.
	cfg = NewConfig()

	// [user[:password]@][net[(addr)]]/dbname[?param1=value1&paramN=valueN]
	// Find the last '/' (since the password or the net addr might contain a '/')
	foundSlash := false
	for i := len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			foundSlash = true
			var j, k int

			// left part is empty if i <= 0
			if i > 0 {
				// [username[:password]@][protocol[(address)]]
				// Find the last '@' in dsn[:i]
				for j = i; j >= 0; j-- {
					if dsn[j] == '@' {
						// username[:password]
						// Find the first ':' in dsn[:j]. It is the password
						// delimiter; the username itself never contains a raw
						// colon because FormatDSN percent-escapes it.
						for k = 0; k < j; k++ { // We cannot use k = range j here, because we use dsn[:k] below
							if dsn[k] == ':' {
								cfg.Passwd = unescapeUserinfo(dsn[k+1 : j])
								break
							}
						}
						cfg.User = unescapeUserinfo(dsn[:k])

						break
					}
				}

				// [protocol[(address)]]
				// Find the first '(' in dsn[j+1:i]
				for k = j + 1; k < i; k++ {
					if dsn[k] == '(' {
						// dsn[i-1] must be == ')' if an address is specified
						if dsn[i-1] != ')' {
							if strings.ContainsRune(dsn[k+1:i], ')') {
								return nil, errInvalidDSNUnescaped
							}
							return nil, errInvalidDSNAddr
						}
						cfg.Addr = dsn[k+1 : i-1]
						break
					}
				}
				cfg.Net = dsn[j+1 : k]
			}

			// dbname[?param1=value1&...&paramN=valueN]
			// Find the first '?' in dsn[i+1:]
			for j = i + 1; j < len(dsn); j++ {
				if dsn[j] == '?' {
					if err = parseDSNParams(cfg, dsn[j+1:]); err != nil {
						return nil, err
					}
					break
				}
			}

			dbname := dsn[i+1 : j]
			if cfg.DBName, err = url.PathUnescape(dbname); err != nil {
				return nil, fmt.Errorf("invalid dbname %q: %w", dbname, err)
			}

			break
		}
	}

	if !foundSlash && len(dsn) > 0 {
		return nil, errInvalidDSNNoSlash
	}

	if err = cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseDSNBool parses a boolean DSN parameter and names the parameter in the
// error so misconfiguration points at the offending field.
func parseDSNBool(name, value string) (bool, error) {
	v, ok := readBool(value)
	if !ok {
		return false, fmt.Errorf("invalid %s value %q: want one of true, false, 1, 0", name, value)
	}
	return v, nil
}

// parseDSNDuration parses a duration DSN parameter (time.ParseDuration syntax,
// e.g. "500ms", "1s", "2m30s") and names the parameter in the error.
func parseDSNDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: %w", name, value, err)
	}
	return d, nil
}

// parseDSNCharset splits and validates a comma-delimited charset parameter.
// Empty entries (e.g. a trailing comma or ",,") are rejected and the field
// name is included in the error.
func parseDSNCharset(value string) ([]string, error) {
	charsets := strings.Split(value, ",")
	for i, charset := range charsets {
		if strings.TrimSpace(charset) == "" {
			return nil, fmt.Errorf("invalid charset value %q: empty charset at position %d", value, i+1)
		}
	}
	return charsets, nil
}

// parseDSNParams parses the DSN "query string".
// Values must be url.QueryEscape'ed. Unknown parameter names do not fail
// parsing: they are kept as connection parameters (system variables) and a
// warning is logged, so DSNs migrated from other clients keep working.
func parseDSNParams(cfg *Config, params string) (err error) {
	for v := range strings.SplitSeq(params, "&") {
		key, value, found := strings.Cut(v, "=")
		if !found {
			continue
		}

		// cfg params
		switch key {
		// Disable INFILE allowlist / enable all files
		case "allowAllFiles":
			if cfg.AllowAllFiles, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Use cleartext authentication mode (MySQL 5.5.10+)
		case "allowCleartextPasswords":
			if cfg.AllowCleartextPasswords, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Allow fallback to unencrypted connection if server does not support TLS
		case "allowFallbackToPlaintext":
			if cfg.AllowFallbackToPlaintext, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Use native password authentication
		case "allowNativePasswords":
			if cfg.AllowNativePasswords, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Use old authentication mode (pre MySQL 4.1)
		case "allowOldPasswords":
			if cfg.AllowOldPasswords, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Check connections for Liveness before using them
		case "checkConnLiveness":
			if cfg.CheckConnLiveness, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Switch "rowsAffected" mode
		case "clientFoundRows":
			if cfg.ClientFoundRows, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// charset
		case "charset":
			if cfg.charsets, err = parseDSNCharset(value); err != nil {
				return err
			}

		// Collation
		case "collation":
			cfg.Collation = value

		case "columnsWithAlias":
			if cfg.ColumnsWithAlias, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Compression
		case "compress":
			if cfg.compress, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Enable client side placeholder substitution
		case "interpolateParams":
			if cfg.InterpolateParams, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Time Location
		case "loc":
			if value, err = url.QueryUnescape(value); err != nil {
				return fmt.Errorf("invalid loc value %q: %w", value, err)
			}
			cfg.Loc, err = time.LoadLocation(value)
			if err != nil {
				return fmt.Errorf("invalid loc value %q: %w", value, err)
			}

		// multiple statements in one query
		case "multiStatements":
			if cfg.MultiStatements, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// time.Time parsing
		case "parseTime":
			if cfg.ParseTime, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// I/O read Timeout
		case "readTimeout":
			if cfg.ReadTimeout, err = parseDSNDuration(key, value); err != nil {
				return err
			}

		// Reject read-only connections
		case "rejectReadOnly":
			if cfg.RejectReadOnly, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// Server public key
		case "serverPubKey":
			name, err := url.QueryUnescape(value)
			if err != nil {
				return fmt.Errorf("invalid serverPubKey value %q: %w", value, err)
			}
			cfg.ServerPubKey = name

		// Strict mode
		case "strict":
			panic("strict mode has been removed. See https://github.com/go-sql-driver/mysql/wiki/strict-mode")

		// Dial Timeout
		case "timeout":
			if cfg.Timeout, err = parseDSNDuration(key, value); err != nil {
				return err
			}

		// time.Time truncation
		case "timeTruncate":
			if cfg.timeTruncate, err = parseDSNDuration(key, value); err != nil {
				return err
			}

		// Treat TINYINT(1) as boolean
		case "tinyInt1IsBool":
			if cfg.tinyInt1IsBool, err = parseDSNBool(key, value); err != nil {
				return err
			}

		// TLS-Encryption
		case "tls":
			boolValue, isBool := readBool(value)
			if isBool {
				if boolValue {
					cfg.TLSConfig = "true"
				} else {
					cfg.TLSConfig = "false"
				}
			} else if vl := strings.ToLower(value); vl == "skip-verify" || vl == "preferred" {
				cfg.TLSConfig = vl
			} else {
				name, err := url.QueryUnescape(value)
				if err != nil {
					return fmt.Errorf("invalid tls value %q: %w", value, err)
				}
				cfg.TLSConfig = name
			}

		// I/O write Timeout
		case "writeTimeout":
			if cfg.WriteTimeout, err = parseDSNDuration(key, value); err != nil {
				return err
			}
		case "maxAllowedPacket":
			cfg.MaxAllowedPacket, err = strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid maxAllowedPacket value %q: %w", value, err)
			}

		// Connection attributes
		case "connectionAttributes":
			connectionAttributes, err := url.QueryUnescape(value)
			if err != nil {
				return fmt.Errorf("invalid connectionAttributes value %q: %w", value, err)
			}
			cfg.ConnectionAttributes = connectionAttributes

		default:
			// Unknown parameters are kept as connection parameters (system
			// variables sent with SET) instead of failing the whole parse, so
			// DSNs containing historical or foreign parameters still connect.
			// Warn only when the name looks like a misspelling of a driver
			// parameter, so ordinary system variables stay silent.
			if key != "" {
				if suggestion := suggestDSNParam(key); suggestion != "" {
					cfg.Logger.Print("unknown DSN parameter: ", key, " (did you mean ", suggestion, "?)")
				}
			}

			// Tolerate malformed percent-escapes in migrated parameter values:
			// keep the raw value with a warning rather than dropping the DSN.
			unescaped, unescapeErr := url.QueryUnescape(value)
			if unescapeErr != nil {
				cfg.Logger.Print("invalid URL escape in DSN parameter ", key, ": ", unescapeErr)
				unescaped = value
			}

			// lazy init
			if cfg.Params == nil {
				cfg.Params = make(map[string]string)
			}

			// Keep the last occurrence of a duplicate parameter, matching the
			// existing map semantics, and place it at its last position.
			if i := slices.Index(cfg.paramOrder, key); i >= 0 {
				cfg.paramOrder = slices.Delete(cfg.paramOrder, i, i+1)
			}
			cfg.Params[key] = unescaped
			cfg.paramOrder = append(cfg.paramOrder, key)
		}
	}

	return
}

func ensureHavePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "3306")
	}
	return addr
}

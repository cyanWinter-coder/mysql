// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import "sync"

// stmtCache keeps prepared statements alive for repeated use on one
// connection. MySQL statement IDs are connection scoped, so a cache belongs to
// a mysqlConn and is discarded together with the network connection.
type stmtCache struct {
	mu    sync.Mutex
	stmts map[string]*mysqlStmt
}

func newStmtCache() *stmtCache {
	return &stmtCache{stmts: make(map[string]*mysqlStmt)}
}

func (c *stmtCache) get(query string) (*mysqlStmt, bool) {
	if c == nil || query == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stmt, ok := c.stmts[query]
	return stmt, ok
}

// acquire returns an independently closable handle for a cached physical
// statement. The reference count ensures that closing one Prepare handle does
// not deallocate the server statement while another handle still uses it.
func (c *stmtCache) acquire(query string) (*mysqlStmt, bool) {
	stmt, ok := c.get(query)
	if !ok || stmt == nil || stmt.refs == nil {
		return nil, false
	}
	stmt.refs.retain()
	return stmt.newHandle(), true
}

func (c *stmtCache) put(query string, stmt *mysqlStmt) {
	if c == nil || query == "" || stmt == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stmts == nil {
		c.stmts = make(map[string]*mysqlStmt)
	}
	c.stmts[query] = stmt
}

// remove deletes query only when it still names expected. A nil expected value
// removes the entry unconditionally. This avoids removing a replacement
// created after a stale statement was closed.
func (c *stmtCache) remove(query string, expected *mysqlStmt) bool {
	if c == nil || query == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if stmt, ok := c.stmts[query]; ok && (expected == nil || stmt == expected) {
		delete(c.stmts, query)
		return true
	}
	return false
}

func (c *stmtCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.stmts)
}

func (c *stmtCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.stmts)
}

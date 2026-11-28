/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ruleName is the one spelling every identifier this store declares takes: lowerCamelCase
// with an acronym written as a word, so a row reads the same names as the struct it scans
// into and the JSON its callers carry. Two adjacent capitals are an acronym kept in
// capitals; one trailing capital is a one-letter final word.
var ruleName = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)*[A-Z]?$`)

// The sessions table and its indexes are declared in that one spelling, the columns InitSchema adds to an older table included.
func TestTheSchemaDeclaresOnlyRuleNames(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := keyedSQLStore(t, db).InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	bad := ruleBreakingNames(t, ctx, db)
	if len(bad) > 0 {
		t.Fatalf("the schema declares %d names outside the rule: %q", len(bad), bad)
	}
}

// ruleBreakingNames reads the live schema: every table, index and trigger name, and every
// column as table.column, that ruleName refuses. SQLite's own objects are its names.
func ruleBreakingNames(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT type, name FROM sqlite_master`)
	if err != nil {
		t.Fatal(err)
	}
	type object struct{ kind, name string }
	var objects []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(strings.ToLower(o.name), "sqlite_") {
			objects = append(objects, o)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, o := range objects {
		if !ruleName.MatchString(o.name) {
			bad = append(bad, o.name)
		}
		if o.kind != "table" {
			continue
		}
		cols, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, o.name)
		if err != nil {
			t.Fatal(err)
		}
		for cols.Next() {
			var c string
			if err := cols.Scan(&c); err != nil {
				t.Fatal(err)
			}
			if !ruleName.MatchString(c) {
				bad = append(bad, o.name+"."+c)
			}
		}
		if err := cols.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	return bad
}

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import "testing"

// A Host's port and an IPv6 literal's brackets come off; nothing else of the host does.
func TestHostWithoutPortKeepsAnIPv6Literal(t *testing.T) {
	for in, want := range map[string]string{
		"app.example.com":     "app.example.com",
		"app.example.com:443": "app.example.com",
		"[2001:db8::1]:8443":  "2001:db8::1",
		"[2001:db8::1]":       "2001:db8::1",
		"[::1]:443":           "::1",
		"localhost:8080":      "localhost",
	} {
		if got := hostWithoutPort(in); got != want {
			t.Errorf("hostWithoutPort(%q) = %q, want %q", in, got, want)
		}
	}
}

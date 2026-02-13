package ipmatcher

import "testing"

func mustMatcher(t *testing.T, rules []string) *Matcher {
	t.Helper()
	m, err := NewMatcher(rules)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}
	return m
}

func TestMatcherContains(t *testing.T) {
	m := mustMatcher(t, []string{
		"192.168.1.10",
		"10.0.0.0/24",
		"172.16.1.10 - 172.16.1.20",
		"2001:db8::1",
		"2001:db8:1::/48",
		"2408:8000::1-2408:8000::ffff",
	})

	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.10", true},
		{"192.168.1.11", false},
		{"10.0.0.200", true},
		{"10.0.1.1", false},
		{"172.16.1.15", true},
		{"172.16.1.9", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"2001:db8:1::abcd", true},
		{"2001:db8:2::abcd", false},
		{"2408:8000::2", true},
		{"2408:8001::2", false},
	}

	for _, tc := range cases {
		if got := m.Contains(tc.ip); got != tc.want {
			t.Fatalf("Contains(%q)=%v want=%v", tc.ip, got, tc.want)
		}
	}
}

func TestMergeRanges(t *testing.T) {
	m := mustMatcher(t, []string{"10.0.0.1-10.0.0.10", "10.0.0.11", "10.0.0.12/31"})
	if !m.Contains("10.0.0.13") {
		t.Fatalf("expected 10.0.0.13 to be included")
	}
	if m.Contains("10.0.0.14") {
		t.Fatalf("expected 10.0.0.14 to be excluded")
	}
}

func TestInvalidRules(t *testing.T) {
	_, err := NewMatcher([]string{"192.168.1.1-2001:db8::1"})
	if err == nil {
		t.Fatalf("expected mixed-version range to fail")
	}
}

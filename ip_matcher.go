package ipmatcher

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type interval struct {
	start uint128
	end   uint128
}

type index struct {
	ends   []uint128
	ranges []interval
}

func (idx index) contains(v uint128) bool {
	i := sort.Search(len(idx.ends), func(i int) bool {
		return !idx.ends[i].less(v)
	})
	if i == len(idx.ranges) {
		return false
	}
	r := idx.ranges[i]
	return !v.less(r.start) && !r.end.less(v)
}

// Matcher supports single IP, range and CIDR rules for both IPv4 and IPv6.
type Matcher struct {
	v4 index
	v6 index
}

// NewMatcher builds an immutable matcher from rules.
//
// Supported rule formats:
// - single IP: "192.168.1.10", "2001:db8::1"
// - range: "172.16.1.10-172.16.1.20"
// - CIDR: "10.0.0.0/24", "2001:db8::/32"
func NewMatcher(rules []string) (*Matcher, error) {
	v4Ranges := make([]interval, 0, len(rules))
	v6Ranges := make([]interval, 0, len(rules))

	for _, raw := range rules {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}

		isV4, iv, err := parseRule(r)
		if err != nil {
			return nil, err
		}
		if isV4 {
			v4Ranges = append(v4Ranges, iv)
		} else {
			v6Ranges = append(v6Ranges, iv)
		}
	}

	return &Matcher{v4: buildIndex(v4Ranges), v6: buildIndex(v6Ranges)}, nil
}

// Contains checks whether ip is covered by current rule set.
func (m *Matcher) Contains(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}

	v := addrToUint128(addr)
	if addr.Is4() {
		return m.v4.contains(v)
	}
	return m.v6.contains(v)
}

func buildIndex(ranges []interval) index {
	if len(ranges) == 0 {
		return index{}
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start.less(ranges[j].start)
	})

	merged := make([]interval, 0, len(ranges))
	merged = append(merged, ranges[0])

	for i := 1; i < len(ranges); i++ {
		cur := ranges[i]
		last := &merged[len(merged)-1]

		if !last.end.plusOne().less(cur.start) {
			if last.end.less(cur.end) {
				last.end = cur.end
			}
			continue
		}
		merged = append(merged, cur)
	}

	ends := make([]uint128, len(merged))
	for i, r := range merged {
		ends[i] = r.end
	}

	return index{ends: ends, ranges: merged}
}

func parseRule(rule string) (isV4 bool, iv interval, err error) {
	if strings.Contains(rule, "/") {
		prefix, err := netip.ParsePrefix(rule)
		if err != nil {
			return false, interval{}, fmt.Errorf("invalid CIDR %q: %w", rule, err)
		}
		prefix = prefix.Masked()
		addr := prefix.Addr()
		bits := addr.BitLen()
		ones := prefix.Bits()
		start := addrToUint128(addr)
		hostBits := bits - ones
		mask := lowBitsMask(hostBits)
		end := start.or(mask)
		return addr.Is4(), interval{start: start, end: end}, nil
	}

	if strings.Contains(rule, "-") {
		parts := strings.SplitN(rule, "-", 2)
		if len(parts) != 2 {
			return false, interval{}, fmt.Errorf("invalid range %q", rule)
		}
		left, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, interval{}, fmt.Errorf("invalid range start %q: %w", rule, err)
		}
		right, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, interval{}, fmt.Errorf("invalid range end %q: %w", rule, err)
		}
		if left.Is4() != right.Is4() {
			return false, interval{}, fmt.Errorf("range IP versions mismatch: %q", rule)
		}

		s := addrToUint128(left)
		e := addrToUint128(right)
		if e.less(s) {
			return false, interval{}, fmt.Errorf("range start larger than end: %q", rule)
		}
		return left.Is4(), interval{start: s, end: e}, nil
	}

	addr, err := netip.ParseAddr(rule)
	if err != nil {
		return false, interval{}, fmt.Errorf("invalid IP %q: %w", rule, err)
	}
	v := addrToUint128(addr)
	return addr.Is4(), interval{start: v, end: v}, nil
}

type uint128 struct {
	hi uint64
	lo uint64
}

func (a uint128) less(b uint128) bool {
	if a.hi != b.hi {
		return a.hi < b.hi
	}
	return a.lo < b.lo
}

func (a uint128) plusOne() uint128 {
	lo := a.lo + 1
	hi := a.hi
	if lo == 0 {
		hi++
	}
	return uint128{hi: hi, lo: lo}
}

func (a uint128) or(b uint128) uint128 {
	return uint128{hi: a.hi | b.hi, lo: a.lo | b.lo}
}

func lowBitsMask(n int) uint128 {
	if n <= 0 {
		return uint128{}
	}
	if n >= 128 {
		return uint128{hi: ^uint64(0), lo: ^uint64(0)}
	}
	if n >= 64 {
		low := ^uint64(0)
		highBits := n - 64
		var hi uint64
		if highBits == 64 {
			hi = ^uint64(0)
		} else {
			hi = (uint64(1) << highBits) - 1
		}
		return uint128{hi: hi, lo: low}
	}
	return uint128{hi: 0, lo: (uint64(1) << n) - 1}
}

func addrToUint128(addr netip.Addr) uint128 {
	a16 := addr.As16()
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = (hi << 8) | uint64(a16[i])
	}
	for i := 8; i < 16; i++ {
		lo = (lo << 8) | uint64(a16[i])
	}
	return uint128{hi: hi, lo: lo}
}

package Firewall

import (
	"net"
	"testing"
)

func TestRule_compile(t *testing.T) {

	rule := &Rule{
		Kind:   allowed,
		Ranges: []string{"10.5.0.1/16"},
	}
	if _, _, err := rule.compile(); err != nil {
		t.Error(err)
		return
	}

	if len(rule.ipRanges) != 1 {
		t.Error("compile ipRanges error")
		t.Skip()
	}

	if !net.IPv4(10, 5, 0, 0).Equal(rule.ipRanges[0].IP) {
		t.Error("compile ipRanges[0].IP error", rule.ipRanges[0].IP)
	}

	if rule.ipRanges[0].Mask.String() != "ffff0000" {
		t.Error("compile ipRanges[0].Mask error", rule.ipRanges[0].Mask)
	}
}

func TestRule_isMatch(t *testing.T) {

	rule := &Rule{
		// 第2組 00000000 ~ 00111111 = 0 ~ 63
		// 63 = (255 - 192)
		// 192 = (1 << 7) + (1 << 6)
		Kind:   allowed,
		Ranges: []string{"10.0.0.0/10"},
	}
	if _, _, err := rule.compile(); err != nil {
		t.Error(err)
		return
	}

	if !rule.isMatch(net.IPv4(10, 63, 123, 111)) {
		t.Error("rule.IsMach error (not match 00001010.00111111.01111011.01101111)")
	}
	if rule.isMatch(net.IPv4(10, 64, 0, 0)) {
		t.Error("rule.IsMach error (match 00001010.01000000.00000000.00000000)")
	}

	m := net.CIDRMask(8, 32)
	ip := net.IPv4(10, 140, 0, 155)
	ip2 := ip.Mask(m)

	t.Log(m)
	t.Log(ip)
	t.Log(ip2)

}

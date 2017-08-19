package Firewall

import (
	"net"
	"testing"
)

func Test_Allowed(t *testing.T) {

	conf := Config{
		Rules: []*Rule{
			{
				Kind:   allowed,
				Ranges: []string{"52.123.4.5"},
			},
			{
				Kind:   allowed,
				Ranges: []string{"10.5.0.1/16"},
			},
			{
				Kind:   denied,
				Ranges: []string{"0.0.0.0/0"},
			},
		},
	}

	if err := conf.compile(); err != nil {
		t.Error(err)
		t.Skip()
	}

	if !Allowed(conf, net.IPv4(52, 123, 4, 5)) {
		t.Error("error of 52.123.4.5")
	}

	if !Allowed(conf, net.IPv4(10, 5, 255, 255)) {
		t.Error("error of 10.5.255.255")
	}

	if Allowed(conf, net.IPv4(10, 6, 0, 1)) {
		t.Error("error of 10.6.0.1")
	}

	if Allowed(conf, net.IPv4(192, 168, 0, 1)) {
		t.Error("error of 192.198.0.1")
	}

}

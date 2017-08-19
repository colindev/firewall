package Firewall

import (
	"errors"
	"net"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

const (
	allowed = "allowed"
	denied  = "denied"
)

// ErrKind is an error of config property
var ErrKind = errors.New("kind error")

// IPRange contain net.IP and net.IPMask
type IPRange struct {
	IP   net.IP
	Mask net.IPMask
}

// Rule record a firewall set
type Rule struct {
	Name     string   `yaml:"name"`
	Kind     string   `yaml:"kind"`
	Ranges   []string `yaml:",flow"`
	ipRanges []IPRange
}

func (r *Rule) compile() (string, *Rule, error) {

	r.Kind = strings.ToLower(r.Kind)
	if r.Kind != allowed && r.Kind != denied {
		return "", r, ErrKind
	}

	r.ipRanges = []IPRange{}
	for _, ipRange := range r.Ranges {
		sets := strings.SplitN(ipRange, "/", 2)
		ip := net.ParseIP(sets[0])
		mask := net.IPv4Mask(255, 255, 255, 255)
		if len(sets) == 2 {
			n, _ := strconv.Atoi(sets[1])
			mask = net.CIDRMask(n, 32)
		}
		ip = ip.Mask(mask)
		r.ipRanges = append(r.ipRanges, IPRange{IP: ip, Mask: mask})
	}

	return r.Kind, r, nil
}

func (r *Rule) isMatch(ip net.IP) bool {

	for _, ipRange := range r.ipRanges {
		if ip.Mask(ipRange.Mask).Equal(ipRange.IP) {
			return true
		}
	}

	return false
}

// Config rules
type Config struct {
	Rules []*Rule `yaml:"rules,flow"`
}

func (conf *Config) compile() error {

	for _, rule := range conf.Rules {
		_, _, err := rule.compile()
		if err != nil {
			return err
		}
	}

	return nil
}

// NewConfig return Config struct
func NewConfig(b []byte) (conf Config, err error) {
	conf = Config{}
	err = yaml.Unmarshal(b, &conf)
	if err != nil {
		return
	}
	err = conf.compile()
	return
}

// Allowed if Config has no sets, the default behavior is deny all
var Allowed = func(conf Config, ip net.IP) bool {
	for _, rule := range conf.Rules {
		switch rule.Kind {
		case allowed:
			if rule.isMatch(ip) {
				return true
			}
		case denied:
			if rule.isMatch(ip) {
				return false
			}
		}
	}
	return false
}

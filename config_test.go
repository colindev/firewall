package Firewall

import "testing"

func TestConfig(t *testing.T) {
	content := `
rules:
  - name: xxx
    kind: allowed
    ranges:
      - 10.0.0.0/8
    ports:
      - 80-81 
`

	conf, err := NewConfig([]byte(content))
	if err != nil {
		t.Error(err)
		t.Skip()
	}
	if len(conf.Rules) == 0 {
		t.Error("read error")
		t.Skip()
	}
	if conf.Rules[0].Name != "xxx" {
		t.Error("rules[0].name")
	}
	if conf.Rules[0].Kind != allowed {
		t.Error("rules[0].kind")
	}
	if len(conf.Rules[0].Ranges) == 0 {
		t.Error("rules[0].ranges")
	} else if conf.Rules[0].Ranges[0] != "10.0.0.0/8" {
		t.Error("rules[0].ranges[0]")
	}
	t.Logf("%#v", conf)
	t.Log(err)
}

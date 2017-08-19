### Firewall

[![GoDoc](https://godoc.org/github.com/colindev/firewall?status.svg)](https://godoc.org/github.com/colindev/firewall)


#### Config Schema (YAML)

priority is sort by ASC, if not any rules all ip denied

```
rules:
  - name: rule-name
    kind: allowed
    ranges:
      - 10.0.0.0/8

  - name: rule-name
    kind: denied
    ranges:
      - 0.0.0.0/0

```

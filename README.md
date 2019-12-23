# go_scan
go_scan is a simple tcp scanner written in golang. 

**Author**: [th3jiv3r][twitter]

### New Features!
  - go_scan takes arguments for host and port(s)

### Installation
```sh
$ go get github.com/goodlandsecurity/go_scan/go_scan
$ cd ~/go/src/github.com/goodlandsecurity/go_scan/cmd
$ go build goscan.go
```

### Example Use:  
  - *goscan localhost 22*
  - *goscan 10.0.0.1 22,80,443,3389*
  - *goscan 192.168.0.1 1-65535*

#### License
  - GNU General Public License v3.0


[twitter]: <https://twitter.com/th3_jiv3r>

# go_scan
go_scan is a simple tcp scanner written in golang. 

**Author**: [th3jiv3r][twitter]

### New Features!
  - displays services running on open ports in scan results
  - go_scan uses flags for host and port(s)
  - -host flag must be provided to run
  - by default, if -port flag is not provided go_scan will use the top 20 most scanned ports

### Installation
```sh
$ go get github.com/goodlandsecurity/go_scan/go_scan
$ cd ~/go/src/github.com/goodlandsecurity/go_scan/cmd
$ go build goscan.go
```

### Example Use:  
  - *goscan -host localhost*
  - *goscan -host 10.0.0.1 -port 22,80*
  - *goscan -host 192.168.0.1 -port 21-25,80,443-445,3389*

#### License
  - GNU General Public License v3.0


[twitter]: <https://twitter.com/th3_jiv3r>

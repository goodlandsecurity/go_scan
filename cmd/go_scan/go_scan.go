package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"

	"github.com/goodlandsecurity/go_scan/go_scan"
)

// default ports to be scanned if -port flag is not used
const (
	top20 = "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
)
var (
hostFlag = flag.String("host", "", "<-host> hostname or ip address")
portFlag = flag.String("port", top20, "[-port] single port, range of ports, or mix of both")
)

func worker(ports, results chan int) {
	for p := range ports {
		if *hostFlag == "" {
			flag.PrintDefaults()
			os.Exit(1)
		}
		address := fmt.Sprintf("%v:%d", *hostFlag, p)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			// if port is closed, send 0
			results <- 0
			continue
		}
		conn.Close()
		// if port is opened, send port
		results <- p
	}
}

func main() {
	flag.Parse()
	fmt.Printf("Starting scan of host %s...\n\n", *hostFlag)
	ports := make(chan int, 100)
	// create a separate channel to communicate the results from the worker to the main thread 
	results := make(chan int)
	// store the results in a slice to sort later
	var openPorts []int

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	portParse, err := go_scan.Parse(*portFlag)

	if err != nil {
		log.Panicln(err)
	}

	for _, parsed := range portParse {
		ports <- parsed
		port := <- results
		if port != 0 {
			openPorts = append(openPorts, port)
		}
	}

	close(ports)
	close(results)
	// sort the slice of open ports
	sort.Ints(openPorts)
	// loop over the slice and print the open ports and the service running on the port
	for _, port := range openPorts {
		service := go_scan.TCPServices[port]
			fmt.Printf("%d open %s\n", port, service)
	}
}

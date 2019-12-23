package main

import (
	"fmt"
	"net"
	"os"
	"log"
	"sort"

	"github.com/goodlandsecurity/go_scan/go_scan"
)

func worker(ports, results chan int) {
	for p := range ports {
		host := os.Args[1]
		address := fmt.Sprintf("%v:%d", host, p)
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
	ports := make(chan int, 100)
	// create a separate channel to communicate the results from the worker to the main thread 
	results := make(chan int)
	// store the results in a slice to sort later
	var openports []int

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	portParse, err := tcp_scanner.Parse(os.Args[2])
	if err != nil {
		log.Panicln(err)
	}

	for _, parsed := range portParse {
		ports <- parsed
		port := <- results
		if port != 0 {
			openports = append(openports, port)
		}
	}

	close(ports)
	close(results)
	// sort the slice of open ports
	sort.Ints(openports)
	// loop over the slice and print the open ports
	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}
}


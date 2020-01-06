package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/goodlandsecurity/go_scan/go_scan"
	"gopkg.in/gookit/color.v1"
)

// default ports to be scanned if -port flag is not used
const (
	top20 = "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
)
var (
	w = new(tabwriter.Writer)
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
		// if port is open, send port
		results <- p
	}
}

func main() {
	start := time.Now()
	flag.Parse()
	ports := make(chan int, 100)
	// create a separate channel to communicate the results from the worker to the main thread 
	results := make(chan int)
	// store the results in a slice to sort later
	var openPorts []int

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}
	fmt.Printf("Starting scan of host %s...\n\n", *hostFlag)

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

	if len(openPorts) > 0 {
                w.Init(os.Stdout, 0, 8, 2, '\t', 0)
                fmt.Fprintf(w, "PORT\tSTATUS\tSERVICE\n____\t______\t_______\n")
                w.Flush()
                // loop over the slice and print the open ports and the service running on the port
                for _, port := range openPorts {
                        service := go_scan.TCPServices[port]
                        fmt.Fprintf(w,"%v\topen\t%v\n", port, service)
                        w.Flush()
                }
                elapsed := time.Since(start)
                fmt.Printf("\nScan took %+v to complete!", elapsed)
        } else {
                color.Red.Println("No open ports!")
        }
}

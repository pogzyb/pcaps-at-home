package main

import (
	"./pcapture"
	"flag"
	"log"
	"os"
)

const SSLKeyLogFile string = "SSLKEYLOGFILE"

var dvc = flag.String("dvc", "", "The network device to listen on.")
var dst = flag.String("dst", ".", "The output directory where pcap files will be written.")
var fn = flag.String("fn", "traffic.pcap", "The base filename for pcap files.")
var rt = flag.Int("rt", 10, "The interval ")
var ts = flag.String("ts", "2006-01-02.15:04:05", "The timestamp format for writing pcap files")

func main() {
	flag.Parse()
	// check for SSL key log file
	ok := os.Getenv(SSLKeyLogFile)
	if ok == "" {
		log.Fatalf("environment variable %s must be set", SSLKeyLogFile)
	}
	if *dvc == "" {
		log.Fatalf("must specify a device with argument: -dvc")
	}
	// start capturing pcap logs
	log.Printf("capturing traffic on %s", *dvc)
	log.Fatal(pcapture.Run(*fn, *ts, *dst, *dvc, *rt))
}

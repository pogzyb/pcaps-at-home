package pcapture

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	snapLength 	uint32		  = 65536 // pcap packet takes unsigned int
	timeout		time.Duration = 15 * time.Second
	mutex 		sync.Mutex
)

type PCAPWriter struct {
	pcapName  	string
	timeFormat  string
	destination string
	handle      *pcap.Handle
	file        *os.File
	writer      *pcapgo.Writer
}

func (pw *PCAPWriter) handlePacket(p *gopacket.Packet) {}

// Generates a PCAP filename based on the current time
func (pw *PCAPWriter) filename() string {
	ts := time.Now().UTC().Format(pw.timeFormat)
	return fmt.Sprintf("%s.%s.%s", pw.pcapName, ts, "pcap")
}

// Writes packets to the current PCAP file
func (pw *PCAPWriter) capture(source *gopacket.PacketSource) {
	for packet := range source.Packets() {
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			//go handlePacket(packet)
			fmt.Println("Application layer/Payload found.")
			fmt.Printf("%s\n", applicationLayer.Payload())
			// Search for a string inside the payload
			if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
				fmt.Println("HTTP found!")
			}
		}
		if err := pw.writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Printf("could not write packet to file: %v", err)
		}
	}
}

// Opens a new file and creates a new pcapgo "Writer" for the file
func (pw *PCAPWriter) swapWriter() error {
	filename := pw.filename()
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, os.FileMode(644)) // todo: configurable?
	if err != nil {
		return err
	}
	pw.writer = pcapgo.NewWriter(f)
	if err := pw.writer.WriteFileHeader(snapLength, layers.LinkTypeEthernet); err != nil {
		return err
	}
	pw.file = f
	return nil
}

// Attempts to close the current PCAP file
func (pw *PCAPWriter) close() error {
	if pw.file == nil {
		return nil
	}
	err := pw.file.Close()
	pw.writer = nil
	pw.file = nil
	return err
}

// Rotates the file and writer references
func (pw *PCAPWriter) rotate() {
	mutex.Lock()
	defer mutex.Unlock()
	err := pw.close()
	if err != nil {
		log.Printf("could not close current pcap file: %v", err)
	}
	err = pw.swapWriter()
	if err != nil {
		log.Printf("could not swap pcap writers: %v", err)
	}
}

// Sets the PCAPWriter handle for the given network device
func (pw *PCAPWriter) openDevice(device string) error {
	handle, err := pcap.OpenLive(device, int32(snapLength), true, timeout)
	if err != nil {
		return err
	}
	pw.handle = handle
	return nil
}

// Ran as goroutine; Signals for file rotation based on the current time
func signal(rotate chan struct{}, interval int) {
	for {
		now := time.Now().UTC()
		switch now.Minute() % interval {
		case 0:
			rotate <- struct{}{}
			time.Sleep(time.Minute)
		default:
			time.Sleep(time.Second)
		}
	}
}

// Entry point for this program
func Run(pcapName, timeFormat, destination, device string, interval int) error {
	// init PCAPWriter
	pw := &PCAPWriter{
		pcapName: pcapName,
		timeFormat: timeFormat,
		destination: destination,
	}
	// open network device
	err := pw.openDevice(device)
	if err != nil {
		return fmt.Errorf("could not open network device %s: %v", device, err)
	}
	if err := pw.swapWriter(); err != nil {
		return fmt.Errorf("could not setup pcap writer: %v", err)
	}
	// get packet source object for packet iteration
	source := gopacket.NewPacketSource(pw.handle, pw.handle.LinkType())
	// start capturing traffic
	go pw.capture(source)
	// start the rotate timer
	timer := make(chan struct{})
	go signal(timer, interval)
	for {
		select {
		// listen for the rotate signal
		case <-timer:
			//fileToParse := pw.file.Name()
			// rotate; close the current file and open a new one file
			pw.rotate()
			// parse the pcap file that was just closed
			//go pw.parsePCAP(fileToParse)
		default:
			time.Sleep(time.Second)
		}
	}
}

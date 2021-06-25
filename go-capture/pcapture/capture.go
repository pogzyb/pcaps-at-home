package pcapture

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	snapLength uint32 = 65536 // pcap packet takes unsigned int
	timeout           = 15 * time.Second
	mutex      sync.Mutex
	// timer for rotating files
	timer = make(chan struct{})
	// interrupt exit signaler
	exit = make(chan os.Signal, 1)
	// counting semaphore
	sema = make(chan struct{}, 50)
)

type PCAPWriter struct {
	pcapName    string
	timeFormat  string
	destination string
	handle      *pcap.Handle
	file        *os.File
	writer      *pcapgo.Writer
}

// Ran as a goroutine; Handles writing packet information to the PCAPWriter file
func (pw *PCAPWriter) handlePacket(p gopacket.Packet, ctx context.Context) {
	select {
	// acquire token
	case sema <- struct{}{}:
	// poll cancellation
	case <-ctx.Done():
		log.Println("cancelled work")
		return
	}
	// release token on completion
	defer func() { <-sema }()
	// todo: decrypt application payloads with SSL keys
	//applicationLayer := p.ApplicationLayer()
	//if applicationLayer != nil {
	//	//go handlePacket(packet)
	//	fmt.Println("Application layer/Payload found.")
	//	fmt.Printf("%s\n", applicationLayer.Payload())
	//	// Search for a string inside the payload
	//	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
	//		fmt.Println("HTTP found!")
	//	}
	//}
	if err := pw.writer.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
		log.Printf("could not write packet to file: %v", err)
	}
}

// Generates a PCAP filename based on the current time
func (pw *PCAPWriter) filename() string {
	ts := time.Now().UTC().Format(pw.timeFormat)
	return fmt.Sprintf("%s.%s.%s", pw.pcapName, ts, "pcap")
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
func watch(rotate chan struct{}, interval int) {
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
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	// init PCAPWriter
	pw := &PCAPWriter{
		pcapName:    pcapName,
		timeFormat:  timeFormat,
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
	// create context for goroutines
	ctx, cancel := context.WithCancel(context.Background())
	// start capturing traffic
	go func(source *gopacket.PacketSource) {
		defer cancel()
		packets := source.Packets()
		for packet := range packets {
			go pw.handlePacket(packet, ctx)
		}
	}(source)
	// start the rotate timer
	go watch(timer, interval)
	// multiplex channels
	for {
		select {
		// listen for the rotate timer
		case <-timer:
			//fileToParse := pw.file.Name()
			// rotate; close the current file and open a new one file
			pw.rotate()
			// parse the pcap file that was just closed
			//go pw.parsePCAP(fileToParse)

		// listen for interrupt
		case <-exit:
			cancel()
			// Handle.Close will close the packet source channel
			pw.handle.Close()
			// close the current pcap file
			err := pw.close()
			if err != nil {
				log.Printf("could not close pcap file: %v\n", err)
			}
			os.Exit(1)
		}
	}
}

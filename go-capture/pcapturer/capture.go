package pcapturer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"sync"
	"time"
)

var (
	filePermissions			   = os.FileMode(0444)
	fileTimestampFormat        = "2006-01-02.15:04:05"
	pcapSnapLen         uint32 = 65536

)

type RotatingPCAP struct {
	mutex sync.Mutex

	baseFileName   string
	baseFileSuffix string

	outputPathPCAP string
	outputPathCSV  string

	deviceHandle  *pcap.Handle
	currentFile   *os.File
	currentWriter *pcapgo.Writer
}

// Generates a filename based on the current time and RotatingPCAP's configurations
func (r *RotatingPCAP) getFilename() string {
	fileTimestamp := time.Now().UTC().Format(fileTimestampFormat)
	filename := fmt.Sprintf("%s.%s.%s", r.baseFileName, fileTimestamp, r.baseFileSuffix)
	return filename
}

// Writes packets to the current PCAP file
func (r *RotatingPCAP) capturePacketsFromSource(source *gopacket.PacketSource) {
	for packet := range source.Packets() {
		if err := r.currentWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Printf("Could not write pcap to file!\n%s", err.Error())
		}
	}
}

// Opens a new file and creates a new pcapgo "Writer" for the file
func (r *RotatingPCAP) setUpNewFileAndWriter() error {
	filename := r.getFilename()
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	r.currentWriter = pcapgo.NewWriter(f)
	if err := r.currentWriter.WriteFileHeader(pcapSnapLen, layers.LinkTypeEthernet); err != nil {
		return err
	}
	r.currentFile = f
	return nil
}

// Attempts to close the current PCAP file
func (r *RotatingPCAP) closeCurrentFileAndWriter() error {
	if r.currentFile == nil {
		return nil
	}
	err := r.currentFile.Close()
	r.currentWriter = nil
	r.currentFile = nil
	return err
}

// Rotates the file and writer objects
func (r *RotatingPCAP) rotateFile() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	err := r.closeCurrentFileAndWriter()
	if err != nil {
		log.Fatalf("Could not close current pcap file!\n%s", err.Error())
	}
	err = r.setUpNewFileAndWriter()
	if err != nil {
		log.Fatalf("Could not setup the new pcap file for writing!\n%s", err.Error())
	}
}

// Returns a handle for the given device
func openDevice(device string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, 65535, true, 60)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

// Ran as a Goroutine; Signals for file rotation based on the current time
func rotateAt(rotate chan bool, rotateMinuteInterval int) {
	for {
		now := time.Now().UTC()
		switch now.Minute() % rotateMinuteInterval {
		case 0:
			rotate <- true
			time.Sleep(time.Minute)
		default:
			time.Sleep(time.Second)
		}
	}
}

// Entry point for this program
func Run(device, outputDir string) {
	rotateSignal := make(chan bool)

	pcaptor := RotatingPCAP{
		baseFileName: "packets",
		baseFileSuffix: "pcap",
		mutex: sync.Mutex{},
	}

	pcaptor.deviceHandle, _ = openDevice(device)
	if err := pcaptor.setUpNewFileAndWriter(); err != nil {
		log.Fatalf("Could not setup initial file and pcap writer\n%s", err.Error())
	}
	defer pcaptor.deviceHandle.Close()

	// Set filter
	//filter := "tcp and port 80"
	//err := pcaptor.deviceHandle.SetBPFFilter(filter)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Println("Only capturing TCP port 80 packets.")

	source := gopacket.NewPacketSource(pcaptor.deviceHandle, pcaptor.deviceHandle.LinkType())

	// start capturing traffic
	go pcaptor.capturePacketsFromSource(source)
	// start the rotate timer
	go rotateAt(rotateSignal, 5)

	for {
		select {
		// listen for the rotate signal
		case <-rotateSignal:
			// get the file name that's about to be closed
			currentFileName := pcaptor.currentFile.Name()
			// rotate; close the current file and open a new one file
			pcaptor.rotateFile()
			// parse the file that was just closed
			go parsePCAP(currentFileName, outputDir)
		default:
			time.Sleep(time.Second)
		}
	}
}

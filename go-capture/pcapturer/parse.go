package pcapturer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"path"
	"time"
)

type PacketData struct {
	timestamp	time.Time
	srcIP		string
	dstIP		string
	srcPort		string
	dstPort		string
	protocol	string
	length		uint16
	//id			int
	//checksum	int
	//version		int
	//ihl			int
	//ttl			int
	//tos			int
	//fin			bool
	//syn			bool
	//ack			bool
}

func (p PacketData) String() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d\n",
		p.timestamp, p.srcIP, p.srcPort, p.dstIP, p.dstPort, p.protocol, p.length)
}

func openPCAP(file string) (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

// extracts packet information and converts it into
func parsePCAP(filename, filepath string) {
	file := path.Join(filepath, filename)
	handle, err := openPCAP(file)
	if err != nil {
		log.Println("bad stuff..", err)
		return
	}
	outputFile, err := os.OpenFile("parsedpcap.txt", os.O_CREATE|os.O_WRONLY, filePermissions)
	if err != nil {
		log.Println("Could not open parsed output file:", err)
		return
	}
	defer outputFile.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// ip layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		// tcp layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		// construct a PacketData object
		pd := PacketData{
			timestamp: packet.Metadata().Timestamp,
			srcIP: ip.SrcIP.String(),
			srcPort: tcp.SrcPort.String(),
			dstIP: ip.DstIP.String(),
			dstPort: tcp.DstPort.String(),
			protocol: ip.Protocol.String(),
			length: ip.Length,

		}
		// write PacketData to output file
		_, err := outputFile.Write([]byte(pd.String()))
		if err != nil {
			log.Println("Could not write to output file:", err)
		}


		//if ipLayer != nil {
		//	ip, _ := ipLayer.(*layers.IPv4)
		//
		//	// IP layer variables:
		//	// Version (Either 4 or 6)
		//	// IHL (IP Header Length in 32-bit words)
		//	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		//	// Checksum, SrcIP, DstIP
		//	log.Println("SRC: ", ip.SrcIP)
		//	log.Println("DST: ", ip.DstIP)
		//	log.Println("IHL: ", ip.IHL)
		//	log.Println("Protocol: ", ip.Protocol)
		//	log.Println("Flags: ", ip.Flags)
		//	log.Println("Contents: ", ip.Contents)
		//	log.Println("TOS: ", ip.TOS)
		//	log.Println("TTL: ", ip.TTL)
		//	log.Println("Length: ", ip.Length)
		//	log.Println("Version: ", ip.Version)
		//	log.Println("Padding: ", ip.Padding)
		//	log.Println("Checksum: ", ip.Checksum)
		//}
		//// Let's see if the packet is TCP
		//tcpLayer := packet.Layer(layers.LayerTypeTCP)
		//if tcpLayer != nil {
		//	tcp, _ := tcpLayer.(*layers.TCP)
		//	// TCP layer variables:
		//	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		//	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		//	log.Println("Sequence number: ", tcp.Seq)
		//	log.Println("SRC port number: ", tcp.SrcPort)
		//	log.Println("DST port number: ", tcp.DstPort)
		//	log.Println("ACK: ", tcp.ACK)
		//	log.Println("FIN: ", tcp.FIN)
		//	log.Println("SYN: ", tcp.SYN)
		//	log.Println("Window: ", tcp.Window)
		//
		//}
		//applicationLayer := packet.ApplicationLayer()
		//if applicationLayer != nil {
		//	log.Printf("app payload:\n%s\n", string(applicationLayer.Payload()))
		//	log.Println("--------------------------")
		//
		//}

		// Check for errors
		if err := packet.ErrorLayer(); err != nil {
			log.Println("Error decoding some part of the packet:", err)
		}
	}
	return
}
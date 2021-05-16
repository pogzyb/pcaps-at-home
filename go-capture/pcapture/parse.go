package pcapture
//
//import (
//	"fmt"
//	"github.com/google/gopacket"
//	"github.com/google/gopacket/layers"
//	"github.com/google/gopacket/pcap"
//	"log"
//	"net"
//	"os"
//	"strings"
//	"time"
//)
//
//type PacketData struct {
//	timestamp	time.Time
//	srcIP		string
//	dstIP		string
//	srcPort		string
//	dstPort		string
//	protocol	string
//	length		uint16
//	//id			int
//	//checksum	int
//	//version		int
//	//ihl			int
//	//ttl			int
//	//tos			int
//	//fin			bool
//	//syn			bool
//	//ack			bool
//}
//
//func (p PacketData) String() string {
//	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d\n",
//		p.timestamp, p.srcIP, p.srcPort, p.dstIP, p.dstPort, p.protocol, p.length)
//}
//
//func resolveIP(addr string) string {
//	names, err := net.LookupAddr(addr)
//	if err == nil {
//		return names[0]
//	} else {
//		return ""
//	}
//}
//
//// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
//func getLocalAddress() net.IP {
//	conn, err := net.Dial("udp", "8.8.8.8:80")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer conn.Close()
//
//	localAddr := conn.LocalAddr().(*net.UDPAddr)
//	return localAddr.IP
//}
//
//// Generates a CSV filename based on the time extracted from the corresponding PCAP filename
//func (r *RotatingPCAP) getCSVFilename(pcapFilename string) string {
//	// extract the "timestamp" portion from the pcap file name
//	filenameSplit := strings.Split(pcapFilename, ".")
//	fileTimestamp := strings.Join(filenameSplit[1:3], ".")
//	filename := fmt.Sprintf("%s.%s.%s", r.config.FilenameBase, fileTimestamp, "csv")
//	return filename
//}
//
//// extracts packet information and converts it into
//func (r *RotatingPCAP) parsePCAP(pcapFilename string) {
//	// open the pcap file
//	pcapFileHandle, err := pcap.OpenOffline(pcapFilename)
//	if err != nil {
//		log.Println("Could not open pcap file for parsing:", err)
//		return
//	}
//	defer pcapFileHandle.Close()
//
//	// open CSV output file
//	csvFilename := r.getCSVFilename(pcapFilename)
//	csvFile, err := os.OpenFile(csvFilename, os.O_CREATE|os.O_WRONLY, r.config.FilePermissions)
//	if err != nil {
//		log.Println("Could not open parsed output file:", err)
//		return
//	}
//	defer csvFile.Close()
//
//	// get packet source object for packet iteration
//	source := gopacket.NewPacketSource(pcapFileHandle, pcapFileHandle.LinkType())
//
//	// iterate over the packets within the given pcap file
//	for packet := range source.Packets() {
//		// ip layer
//		ipLayer := packet.Layer(layers.LayerTypeIPv4)
//		ip, ok := ipLayer.(*layers.IPv4)
//		if !ok {
//			log.Println("No ip layer.")
//			continue
//		}
//
//		if ip.SrcIP.String() == localAddress.String() {
//			srcHost := "home"
//		} else {
//			srcHost := resolveIP(ip.SrcIP.String())
//		}
//
//		// tcp layer
//		tcpLayer := packet.Layer(layers.LayerTypeTCP)
//		tcp, ok := tcpLayer.(*layers.TCP)
//		if !ok {
//			log.Println("No tcp layer.")
//			continue
//		}
//		// construct a PacketData object
//		pd := PacketData{
//			timestamp: packet.Metadata().Timestamp.UTC(),
//			srcIP: ip.SrcIP.String(),
//			srcPort: tcp.SrcPort.String(),
//			dstIP: ip.DstIP.String(),
//			dstPort: tcp.DstPort.String(),
//			protocol: ip.Protocol.String(),
//			length: ip.Length,
//		}
//		// write PacketData to output file
//		_, err := csvFile.Write([]byte(pd.String()))
//		if err != nil {
//			log.Println("Could not write packet data to csv file:", err)
//		}
//		// Check for errors
//		if err := packet.ErrorLayer(); err != nil {
//			log.Println("Error decoding some part of the packet:", err)
//		}
//	}
//
//	log.Printf("Finished parsing; data was saved to: %s", csvFile.Name())
//}
//
//
////if ipLayer != nil {
////	ip, _ := ipLayer.(*layers.IPv4)
////
////	// IP layer variables:
////	// Version (Either 4 or 6)
////	// IHL (IP Header Length in 32-bit words)
////	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
////	// Checksum, SrcIP, DstIP
////	log.Println("SRC: ", ip.SrcIP)
////	log.Println("DST: ", ip.DstIP)
////	log.Println("IHL: ", ip.IHL)
////	log.Println("Protocol: ", ip.Protocol)
////	log.Println("Flags: ", ip.Flags)
////	log.Println("Contents: ", ip.Contents)
////	log.Println("TOS: ", ip.TOS)
////	log.Println("TTL: ", ip.TTL)
////	log.Println("Length: ", ip.Length)
////	log.Println("Version: ", ip.Version)
////	log.Println("Padding: ", ip.Padding)
////	log.Println("Checksum: ", ip.Checksum)
////}
////// Let's see if the packet is TCP
////tcpLayer := packet.Layer(layers.LayerTypeTCP)
////if tcpLayer != nil {
////	tcp, _ := tcpLayer.(*layers.TCP)
////	// TCP layer variables:
////	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
////	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
////	log.Println("Sequence number: ", tcp.Seq)
////	log.Println("SRC port number: ", tcp.SrcPort)
////	log.Println("DST port number: ", tcp.DstPort)
////	log.Println("ACK: ", tcp.ACK)
////	log.Println("FIN: ", tcp.FIN)
////	log.Println("SYN: ", tcp.SYN)
////	log.Println("Window: ", tcp.Window)
////
////}
////applicationLayer := packet.ApplicationLayer()
////if applicationLayer != nil {
////	log.Printf("app payload:\n%s\n", string(applicationLayer.Payload()))
////	log.Println("--------------------------")
////
////}

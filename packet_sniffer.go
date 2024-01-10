package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func handler_for_packet(packet gopacket.Packet) {
	// Extract relevant information from the packet
	networkLayer := packet.NetworkLayer()

	if networkLayer != nil {
		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

		// Check if the packet is TCP or UDP

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			fmt.Println("Protocol: TCP")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			fmt.Println("this is a UDP packet")
			fmt.Println("Protocol: UDP")

			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("src port %d dst Port %d\n", udp.SrcPort, udp.DstPort)
		}

		// Display information about the captured packet
		fmt.Printf("Source IP: %s\n", srcIP)
		fmt.Printf("Destination IP: %s\n", dstIP)
		fmt.Println(strings.Repeat("=", 40))
	}
}

func sniffer(device string) {
	handle, err := pcap.OpenLive(device, 1600, true, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handler_for_packet(packet)
	}

}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("use go run packet_sniffer.go <Network Interface>")
		os.Exit(1)
	}
	networkInterface := os.Args[1]
	fmt.Println("we are starting the packet sniffer on \n", networkInterface)
	sniffer(networkInterface)
}

This is a packet sniffer tool written in golang using gopacket lib.
This tool captures the live packets from the network interface and displays the Protocol, src Ipaddress, Destination IPAddress, SrcPort and destination Port 
steps to run the program :
 1. sudo go run packet_sniffer.go en0
to capture the packets on your wifi interface, Type ifconfig on the terminal and select the interface(ethernet, wifi)

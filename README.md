# arp2wol
This is a prototype of a tool to listen for ARP requests to a particular IP address. If such a request is received the tool pings the destination to see if the host is up. If it is not up then it sends a magic pWOL packet to the specified MAC address.

# arguments:
* -d Enable Debug Mode
* -exclude <string> IP Source Address to ignore (e.g. Fritzbox) (default "None")
* -ip <string> IP Address of host to start
* -mac <string> MAC Address of host to start
* -netif <string> Ethernet interface to use (default: eth0) (default "eth0")

Stefan

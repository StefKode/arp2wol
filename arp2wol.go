/***********************************************
 * ARP2WOL
 * Listen for specific ARP request and send out
 * WOL magic packet to wake up host
 * Stefan Koch, 2019
 ************************************************/

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/linde12/gowol"
	"github.com/sparrc/go-ping"
)

var (
	device       string = "wlp4s0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	handle       *pcap.Handle
	WakeIP       string
	WakeMAC      string
	ExcludeSrcIP string
	Debug        bool
)

var reqTrack = make(map[string]int)
var originTrack = make(map[string]string)

func main() {
	fmt.Println("ARP-2-WOL Trigger")
	fmt.Println("-----------------")

	// **************** ARGUMENT HANDLING ************************************
	pEthIf := flag.String("netif", "eth0", "Ethernet interface to use (default: eth0)")
	pWakeIP := flag.String("ip", "", "IP Address of host to start")
	pExcludeSrcIP := flag.String("exclude", "None", "IP Source Address to ignore (e.g. Fritzbox)")
	pWakeMAC := flag.String("mac", "", "MAC Address of host to start")
	pDebug := flag.Bool("d", false, "Debug Mode")
	flag.Parse()

	if *pWakeIP == "" {
		fmt.Println("need IP address")
		return
	}
	if *pWakeMAC == "" {
		fmt.Println("need MAC address")
		return
	}

	testIP := net.ParseIP(*pWakeIP)
	if testIP == nil {
		fmt.Println("Invalid IP address")
		return
	}
	WakeIP = testIP.String()

	testIP = net.ParseIP(*pExcludeSrcIP)
	if testIP == nil {
		fmt.Println("Invalid Exclude IP address")
		return
	}
	ExcludeSrcIP = testIP.String()
	device = *pEthIf
	Debug = *pDebug
	WakeMAC = *pWakeMAC

	//TODO add IP and MAC validation

	fmt.Println("Wakeup NetIF  : " + device)
	fmt.Println("Wakeup IP     : " + WakeIP)
	fmt.Println("Wakeup MAC    : " + WakeMAC)
	fmt.Println("Exclude SrcIP : " + ExcludeSrcIP)
	fmt.Println("Debug         : " + strconv.FormatBool(Debug))

	// **************** INIT CAPTURE  ************************************
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err := handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal(err)
	}

	// **************** EVALUATION LOOP ************************************
	go arpEvaluation()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func debug(s string) {
	if Debug {
		fmt.Printf("# ")
		fmt.Println(s)
	}
}

// send out the magic packet to perform WOL
func wakeup(mac string) {
	debug("wakeup " + mac)
	if packet, err := gowol.NewMagicPacket(mac); err == nil {
		packet.Send("255.255.255.255")
	}
}

// returns true if ip is available
func pingOK(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		panic(err)
	}
	pinger.SetPrivileged(true)

	pinger.Timeout = 2 * time.Second
	pinger.Count = 1
	pinger.Run()
	if pinger.Statistics().PacketsRecv == 1 {
		return true
	}
	return false
}

//gofunction which evaluates the request-Tracking map (reqTrack)
func arpEvaluation() {
	for {
		time.Sleep(1 * time.Second)
		for ip, _ := range reqTrack {
			debug("check " + ip)
			debug("origin " + originTrack[ip])
			if !pingOK(ip) {
				debug("trigger " + ip)
				wakeup(WakeMAC)
				reqTrack[ip] += 1
				if reqTrack[ip] >= 5 {
					delete(reqTrack, ip)
				}
				continue
			}
			delete(reqTrack, ip)
		}
	}
}

//add ip address to tracking map
func addReqTrack(source string, ip string) {
	debug("try addReqTrack ip=" + ip + " source=" + source)
	if ExcludeSrcIP != "None" {
		if source == ExcludeSrcIP {
			debug("exclude match (ignore packet)")
			return
		}
	}
	if ip != WakeIP {
		debug("request " + ip + " not for us (ignore packet)")
		return
	}
	var ok bool
	_, ok = reqTrack[ip]
	if !ok {
		debug("new request (ok)")
		reqTrack[ip] = 1
	} else {
		debug("already seen")
	}
	originTrack[ip] = source
}

func ipString(addr []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

//process each captured packet
func processPacket(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPRequest {
			addReqTrack(ipString(arp.SourceProtAddress), ipString(arp.DstProtAddress))
		}
	}
}

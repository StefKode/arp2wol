all:	arp2wol

arp2wol:	arp2wol.go
		go build arp2wol.go
		strip arp2wol

run:	arp2wol.go
	sudo go run arp2wol.go -ip 192.168.178.48 -mac 00:1F:D0:55:5E:10 -d -netif eth0 -exclude 192.168.178.1

clean:
	rm -f arp2wol

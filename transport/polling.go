package transport

import (
	"chacomm/protocol"
	"github.com/theodesp/blockingQueues"
	"log"
	"strings"
	"time"
)

var packetQueue, _ = blockingQueues.NewArrayBlockingQueue(1024)

func pollRead(stream dnsStream) {
	for {
		time.Sleep(200 * time.Millisecond)
		poll(stream)
	}
}

func poll(stream dnsStream) {

	pollQuery := &chacomm.Message{
		Clientguid: stream.clientGuid,
		Packet: &chacomm.Message_Pollquery{
			Pollquery: &chacomm.PollQuery{},
		},
	}

	pollPacket, err := dnsMarshal(pollQuery, stream.encryptionKey, true)

	if err != nil {
		log.Fatal("Poll marshaling fatal error : %v\n", err)
	}

	answers, err := sendDNSQuery([]byte(pollPacket), stream.targetDomain)
	if err != nil {
		log.Printf("Could not get answer : %v\n", err)
		return
	}

	if len(answers) > 0 {
		packetData := strings.Join(answers, "")
		if packetData == "-" {
			return
		}
		output, complete := Decode(packetData, stream.encryptionKey)
		if complete {
			log.Printf("Final data: %s\n", output)
			packetQueue.Put(output)
		} else {
			/* More data available. Get it !*/
			poll(stream)
		}

	}
}

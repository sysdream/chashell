package transport

import (
	"fmt"
	"github.com/Jeffail/tunny"
	"github.com/rs/xid"
	"io"
	"log"
)

type dnsStream struct {
	targetDomain  string
	encryptionKey string
	clientGuid    []byte
}

func DNSStream(targetDomain string, encryptionKey string) *dnsStream {
	guid := xid.New()
	dnsConfig := dnsStream{targetDomain: targetDomain, encryptionKey: encryptionKey, clientGuid: guid.Bytes()}

	go pollRead(dnsConfig)

	return &dnsConfig
}

func (stream *dnsStream) Read(data []byte) (int, error) {
	packet, err := packetQueue.Get()
	if err != nil {
		return 0, err
	}
	stringData := fmt.Sprintf("%s", packet)
	copy(data, stringData)
	return len(stringData), nil
}

func (stream *dnsStream) Write(data []byte) (int, error) {

	initPacket, dataPackets := Encode(data, true, stream.encryptionKey, stream.targetDomain, stream.clientGuid)

	/*
		Send the "init" packet.
	*/

	_, err := sendDNSQuery([]byte(initPacket), stream.targetDomain)
	if err != nil {
		log.Printf("Unable to send init packet : %v\n", err)
		return 0, io.ErrClosedPipe
	}

	/*
		Send each packets using DNS tunneling.
	*/

	log.Printf("Sending %d packets.\n", len(dataPackets))

	poll := tunny.NewFunc(16, func(packet interface{}) interface{} {
		_, err := sendDNSQuery([]byte(packet.(string)), stream.targetDomain)

		if err != nil {
			log.Printf("Failed to send data packet : %v\n", err)

		}
		return nil
	})
	defer poll.Close()

	for _, packet := range dataPackets {
		poll.Process(packet)
	}

	return len(data), nil
}

package transport

import (
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
	// Generate a "unique" client id.
	guid := xid.New()

	// Specify the stream configuration.
	dnsConfig := dnsStream{targetDomain: targetDomain, encryptionKey: encryptionKey, clientGuid: guid.Bytes()}

	// Poll data from the DNS server.
	go pollRead(dnsConfig)

	return &dnsConfig
}

func (stream *dnsStream) Read(data []byte) (int, error) {
	// Wait for a packet in the queue.
	packet := <- packetQueue
	// Copy it into the data buffer.
	copy(data, packet)
	// Return the number of bytes we read.
	return len(packet), nil
}

func (stream *dnsStream) Write(data []byte) (int, error) {

	// Encode the packets.
	initPacket, dataPackets := Encode(data, true, stream.encryptionKey, stream.targetDomain, stream.clientGuid)

	// Send the init packet to inform that we will send data.
	_, err := sendDNSQuery([]byte(initPacket), stream.targetDomain)
	if err != nil {
		log.Printf("Unable to send init packet : %v\n", err)
		return 0, io.ErrClosedPipe
	}


	// Create a worker pool to asynchronously send DNS packets.
	poll := tunny.NewFunc(4, func(packet interface{}) interface{} {
		_, err := sendDNSQuery([]byte(packet.(string)), stream.targetDomain)

		if err != nil {
			log.Printf("Failed to send data packet : %v\n", err)

		}
		return nil
	})
	defer poll.Close()

	// Send jobs to the pool.
	for _, packet := range dataPackets {
		poll.Process(packet)
	}

	return len(data), nil
}

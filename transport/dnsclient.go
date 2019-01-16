package transport

import (
	"chacomm/crypto"
	"chacomm/protocol"
	"container/list"
	"fmt"
	"github.com/Jeffail/tunny"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
	"time"
)

var currentChunk = 0
var targetDomain = "x.nightlydev.fr"
var packetQueue = list.New()

const (
	DNS_SUCCESS = 0
	ERR_DNS_EXCHANGE = 1 << iota
	ERR_DNS_ERROR = iota
)


func Recv(){
	for {
		time.Sleep(200 * time.Millisecond)
		poll()
	}
}

func poll(){
	nonce, identifier := crypto.Seal([]byte("poll"))
	pollQuery := &chacomm.Message{
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

	a, retcode := sendDNSQuery([]byte(pollPacket))
	if retcode != DNS_SUCCESS {
		log.Printf("Could not get answer !")
		return
	}
	if len(a) > 0 {
		if t, ok := a[0].(*dns.TXT); ok {
			// do something with t.Txt
			log.Printf("Got TXT : %v\n", t.Txt)
			packetTxt := strings.Join(t.Txt, "")
			output, complete := Decode(packetTxt)
			if complete {
				log.Printf("Final data: %s\n", output)
				packetQueue.PushBack(output)
			} else {
				/* More data available. Get it !*/
				poll()
			}

		}

	}
}

func Send(payload []byte)(int, error){

	initPacket, dataPackets := ChunkPackets(payload, true)

	/*
		Send the "init" packet.
		TODO: Encrypt the init packet.
	*/

	sendDNSQuery([]byte(initPacket))

	/*
		Send each packets using DNS tunneling.
	*/


	log.Printf("Sending %d packets.\n", len(dataPackets))

	pool := tunny.NewFunc(16, func(packet interface{}) interface{}{
		_, retCode := sendDNSQuery([]byte(packet.(string)))

		if retCode != 0 {
			log.Printf("Failed to send data packet.")

		}
		return nil
	})
	defer pool.Close()

	for _, packet := range dataPackets {
		pool.Process(packet)
	}

	return len(payload), nil
}


func sendDNSQuery(data []byte) (response []dns.RR, retCode int) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal("error making client from default file", err)
	}

	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fmt.Sprintf("%s.%s", data, targetDomain)), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(conf.Servers[0], conf.Port))

	if err != nil {
		log.Printf("Fatal error : %s", err)
		return nil, ERR_DNS_EXCHANGE
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Printf(" *** Unable to contact DNS server.")
		return nil, ERR_DNS_ERROR
	}

	return r.Answer, DNS_SUCCESS
}
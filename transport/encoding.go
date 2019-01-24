package transport

import (
	"bytes"
	"chacomm/crypto"
	"chacomm/protocol"
	"chacomm/utils"
	"encoding/hex"
	"github.com/golang/protobuf/proto"
	"log"
	"strings"
)

var ChunkMap = map[int32]map[int32]string{}
var Sessions = map[int32]chacomm.ChunkStart{}
var currentChunk = 0

func Decode(payload string, stream dnsStream)(output []byte, complete bool){
	dataPacketRaw, err := hex.DecodeString(payload)

	if err != nil {
		log.Fatal("Invalid packet.\n")
	}

	message := &chacomm.Message{}
	if err := proto.Unmarshal(dataPacketRaw, message); err != nil {
		log.Fatalln("Failed to parse message packet:", err)
	}

	switch u := message.Packet.(type) {
	case *chacomm.Message_Chunkstart:
		Sessions[u.Chunkstart.Chunkid] = *u.Chunkstart
		ChunkMap[u.Chunkstart.Chunkid] = make(map[int32]string)

	case *chacomm.Message_Chunkdata:
		_, valid := Sessions[u.Chunkdata.Chunkid]

		if valid {

			ChunkMap[u.Chunkdata.Chunkid][u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)

			if len(ChunkMap[u.Chunkdata.Chunkid]) == int(Sessions[u.Chunkdata.Chunkid].Chunksize) {
				log.Printf("Hit chunkcount ! We can decrypt !")

				var chunkBuffer bytes.Buffer
				for i := 0; i <= int(Sessions[u.Chunkdata.Chunkid].Chunksize)-1; i++ {
					chunkBuffer.WriteString(string(ChunkMap[u.Chunkdata.Chunkid][int32(i)]))
				}

				output, valid = crypto.Open(chunkBuffer.Bytes(), Sessions[u.Chunkdata.Chunkid].Nonce, stream.encryptionKey)
				if valid {
					return output, true
				} else {
					log.Fatal("Invalid data !\n")
				}
			}
		}
	}
	return nil, false
}

func dnsMarshal(pb proto.Message, isRequest bool)(string, error){
	packet, err := proto.Marshal(pb)

	if err != nil {
		log.Fatal("Unable to marshal packet.\n")
	}

	packetHex := hex.EncodeToString(packet)
	if isRequest {
		packetHex = strings.Join(utils.Splits(packetHex, 63), ".")
	}

	return packetHex, err

}

func Encode(payload []byte, isRequest bool, encryptionKey string, targetDomain string, clientGuid []byte)(initPacket string, dataPackets []string) {
	nonce, message := crypto.Seal(payload, encryptionKey)
	/*
		Chunk the packets so it fits the DNS max length (253)
	 */

	packets := utils.Split(message, (240/2) - len(targetDomain) - len(clientGuid))

	/*
		Increment chunk identifier.
	*/
	currentChunk++

	/*
		Generate the ChunkStart payload
	*/

	init := &chacomm.Message{
		Clientguid: clientGuid,
		Packet:&chacomm.Message_Chunkstart{
			Chunkstart: &chacomm.ChunkStart{
				Nonce: nonce[:],
				Chunkid: int32(currentChunk),
				Chunksize: int32(len(packets)),
			},
		},
	}


	/*
		Generate the protobuf packet.
	*/

	initPacket, err := dnsMarshal(init, isRequest)

	if err != nil {
		log.Fatalf("Init marshaling fatal error : %v\n", err)
	}

	for id, packet := range packets {

		data := &chacomm.Message{
			Clientguid: clientGuid,
			Packet: &chacomm.Message_Chunkdata{
				Chunkdata: &chacomm.ChunkData{
					Chunkid:  int32(currentChunk),
					Chunknum: int32(id),
					Packet:   []byte(packet),
				},
			},
		}


		dataPacket, err := dnsMarshal(data, isRequest)

		if err != nil {
			log.Fatalf("Packet marshaling fatal error : %v\n", err)
		}

		dataPackets = append(dataPackets, dataPacket)

	}
	return initPacket, dataPackets
}
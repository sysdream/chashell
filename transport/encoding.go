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

// ChunkMap should contains the chunk identifier, the chunk number, and the data associated.
var ChunkMap = map[int32]map[int32]string{}
// Sessions should contains the chunk informations about the chunkid associated.
var Sessions = map[int32]chacomm.ChunkStart{}
// Counter to store the current packet identifier.
var currentChunk = 0

func Decode(payload string, encryptionKey string) (output []byte, complete bool) {
	// Decode the packet from hex.
	dataPacketRaw, err := hex.DecodeString(payload)

	if err != nil {
		log.Fatal("Invalid packet.\n")
	}

	// Check if the packet is big enough to fit the nonce.
	if len(dataPacketRaw) <= 24 {
		log.Fatal("Received packet is too small!\n")
	}

	// Authenticate and decrypt the packet.
	output, valid := crypto.Open(dataPacketRaw[24:], dataPacketRaw[:24], encryptionKey)

	// Raise an error if the message is invalid.
	if !valid {
		log.Fatal("Received invalid/corrupted packet.\n")
	}

	// Parse the "Message" part of the Protocol buffer packet.
	message := &chacomm.Message{}
	if err := proto.Unmarshal(output, message); err != nil {
		// This should not append.
		log.Fatalln("Failed to parse message packet:", err)
	}

	// Process the message depending of his type.
	switch u := message.Packet.(type) {
	case *chacomm.Message_Chunkstart:
		// A chunkstart packet indicate that we need to allocate memory to receive data.
		Sessions[u.Chunkstart.Chunkid] = *u.Chunkstart
		ChunkMap[u.Chunkstart.Chunkid] = make(map[int32]string)

	case *chacomm.Message_Chunkdata:
		// Check if we have a valid session from this Chunkid.
		_, valid := Sessions[u.Chunkdata.Chunkid]

		if valid {
			// Fill the ChunkMap with the data from the message.
			ChunkMap[u.Chunkdata.Chunkid][u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)

			// Check if we have successfully received all the packets.
			if len(ChunkMap[u.Chunkdata.Chunkid]) == int(Sessions[u.Chunkdata.Chunkid].Chunksize) {

				// Rebuild the final data.
				var chunkBuffer bytes.Buffer

				for i := 0; i <= int(Sessions[u.Chunkdata.Chunkid].Chunksize)-1; i++ {
					chunkBuffer.WriteString(string(ChunkMap[u.Chunkdata.Chunkid][int32(i)]))
				}

				// Free some memory.
				delete(ChunkMap, u.Chunkdata.Chunkid)
				delete(Sessions, u.Chunkdata.Chunkid)

				// Return the complete data.
				return chunkBuffer.Bytes(), true
			}
		}
	}
	return nil, false
}

func dnsMarshal(pb proto.Message, encryptionKey string, isRequest bool) (string, error) {
	// Convert the Protobuf message to bytes.
	packet, err := proto.Marshal(pb)

	if err != nil {
		log.Fatal("Unable to marshal packet.\n")
	}

	// Encrypt the message.
	nonce, message := crypto.Seal(packet, encryptionKey)

	// Create the data packet containing the nonce and the data.
	packetBuffer := bytes.Buffer{}
	packetBuffer.Write(nonce[:])
	packetBuffer.Write(message)

	// Encode the final packet as hex.
	packetHex := hex.EncodeToString(packetBuffer.Bytes())

	// If this is a DNS Request, subdomains cannot be longer than 63 chars
	// We need to split the packet, then join it using "."
	if isRequest {
		packetHex = strings.Join(utils.Splits(packetHex, 63), ".")
	}

	return packetHex, err

}

func Encode(payload []byte, isRequest bool, encryptionKey string, targetDomain string, clientGuid []byte) (initPacket string, dataPackets []string) {

	// Chunk the packets so it fits the DNS max length (253)
	packets := utils.Split(payload, (240/2)-len(targetDomain)-len(clientGuid)-(24*2))

	// Increment the current chunk identifier
	currentChunk++

	// Generate the init packet, containing informations about the number of chunks.
	init := &chacomm.Message{
		Clientguid: clientGuid,
		Packet: &chacomm.Message_Chunkstart{
			Chunkstart: &chacomm.ChunkStart{
				Chunkid:   int32(currentChunk),
				Chunksize: int32(len(packets)),
			},
		},
	}

	// Transform the protobuf packet into an encrypted DNS packet.
	initPacket, err := dnsMarshal(init, encryptionKey, isRequest)

	if err != nil {
		log.Fatalf("Init marshaling fatal error : %v\n", err)
	}

	// Iterate over every chunks.
	for id, packet := range packets {

		// Generate the "data" packet, containing the current chunk information and data.
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

		// Transform the protobuf packet into an encrypted DNS packet.
		dataPacket, err := dnsMarshal(data, encryptionKey, isRequest)

		if err != nil {
			log.Fatalf("Packet marshaling fatal error : %v\n", err)
		}

		dataPackets = append(dataPackets, dataPacket)

	}
	return initPacket, dataPackets
}

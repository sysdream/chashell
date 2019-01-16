package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

var secretKey = "808b8d0a021c84ad7ff20a5e32877313d6e275477c2ac3263f55f00ada1ecdce"

func Seal(payload []byte)(nonce [24]byte, message []byte){
	/*
		Generate a 24 byte nonce
	*/
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	/*
		Seal message using XSalsa20 + Poly1305
	*/
	var secret [32]byte

	/*
		Decode the symetric encryption key.
	*/

	secretKeyBytes, err := hex.DecodeString(secretKey)
	if err != nil {
		panic(err)
	}

	copy(secret[:], secretKeyBytes)

	message = secretbox.Seal(nil, payload, &nonce, &secret)
	return
}

func Open(payload []byte, in_nonce []byte) (output []byte, valid bool){
	/*
		Seal message using XSalsa20 + Poly1305
	*/
	var secret [32]byte
	var nonce [24]byte
	var out []byte

	/*
		Decode the symetric encryption key.
	*/

	secretKeyBytes, err := hex.DecodeString(secretKey)
	if err != nil {
		panic(err)
	}

	copy(secret[:], secretKeyBytes)

	copy(nonce[:], in_nonce)

	output, valid = secretbox.Open(out, payload, &nonce, &secret)
	return
}
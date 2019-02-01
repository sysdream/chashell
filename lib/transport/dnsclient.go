package transport

import (
	"fmt"
	"net"
)

func sendDNSQuery(data []byte, target string) (responses []string, err error) {
	// We use TXT requests to tunnel data. Feel free to implement your own method.
	responses, err = net.LookupTXT(fmt.Sprintf("%s.%s", data, target))
	return
}

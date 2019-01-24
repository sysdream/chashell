package transport

import (
	"fmt"
	"net"
)


func sendDNSQuery(data []byte, target string)(responses []string, err error){
	responses, err = net.LookupTXT(fmt.Sprintf("%s.%s", data, target))
	return
}

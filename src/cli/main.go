package main

import (
	"fmt"
	"os"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	remoteIP := "127.0.0.1"
	remotePort := 49153
	
	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, "Must provide platform!");
		fmt.Fprintf(os.Stderr, "Usage: %s platform [ip_addr] [port]\n", os.Args[0])
		os.Exit(1)
	}

	platform := os.Args[1]

	if len(os.Args) > 2 {
		remoteIP = os.Args[2]
	}
	if len(os.Args) > 3 {
		port, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid port number: %v\n", err)
			os.Exit(1)
		}
		remotePort = port
	}
	
	fmt.Printf("Platform: %s, IP: %s, Port: %d\n", platform, remoteIP, remotePort)

	meshViewMgr := newMeshViewsMgr(platform, remoteIP, remotePort)
	if meshViewMgr == nil {
		fmt.Println("Failed to create MeshViewsMgr")
		os.Exit(1)
	}



	program = tea.NewProgram(meshViewMgr, tea.WithAltScreen())

	if _, err := program.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

}

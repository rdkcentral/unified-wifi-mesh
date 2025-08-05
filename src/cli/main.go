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
	if len(os.Args) > 1 {
		remoteIP = os.Args[1]
	}
	if len(os.Args) > 2 {
		port, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Errorf("Invalid port number: %v", err)
			os.Exit(1)
		}
		remotePort = port
	}

	meshViewMgr := newMeshViewsMgr(os.Args[0], remoteIP, remotePort)
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

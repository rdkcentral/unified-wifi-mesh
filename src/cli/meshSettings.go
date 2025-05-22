package main

/*          
#cgo CFLAGS: -I../../inc -I../../../OneWifi/include -I../../../OneWifi/source/utils -I../../../halinterface/include
#cgo LDFLAGS: -L../../install/lib -lemcli -lcjson -lreadline
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "em_cli_apis.h"
*/  
import "C"

import (	
	"os"
	"strings"
	"strconv"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model implements tea.Model, and manages the browser UI.
type MeshSettings struct {
	windowWidth  int
	windowHeight int
	remoteAddr	textinput.Model
	dump	*os.File
	ipValid		bool
}

func newMeshSettings(platform string, dump *os.File) *MeshSettings {
	remoteAddr := textinput.New()

    return &MeshSettings {
		remoteAddr:		remoteAddr,	
		dump:			dump,
		ipValid:		false,
	}
}

// Validator of Remote Controller IP Address
func remoteAddrValidator(remoteAddr string) (bool, int, int) {
	var ip int
	var num int

	if ((strings.Count(remoteAddr, ".") != 3) || (strings.Count(remoteAddr, ":") != 1)) {
		return false, 0, 0
	}

	s1 := strings.Split(remoteAddr, ":");
	s2 := strings.Split(s1[0], ".");
		
	for i:= 0; i < len(s2); i++ {
        // statements
		num, err := strconv.Atoi(s2[i])
		if err != nil {
			return false, 0, 0
    	} else if num > 255 {
			return false, 0, 0
		}

		ip |= num << 8*i
    }

	num, _ = strconv.Atoi(s1[1])

	return true, ip, num
}

// Init initialises the Model on program load. It partly implements the tea.Model interface.
func (m *MeshSettings) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles event and manages internal state. It partly implements the tea.Model interface.
func (m *MeshSettings) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd
	var ip int
	var port int

	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
			case "enter":
				m.ipValid, ip, port = remoteAddrValidator(m.remoteAddr.Value())
				C.set_remote_addr(C.uint(ip), C.uint(port), C.bool(m.ipValid))	
		}
	}
	

	m.remoteAddr, cmd = m.remoteAddr.Update(message)
    cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// View applies and styling and handles rendering the view. It partly implements the tea.Model
// interface.
func (m *MeshSettings) View() string {
	foreStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), true).
		BorderForeground(lipgloss.Color("6")).
		Padding(0, 1)

	boldStyle := lipgloss.NewStyle().Bold(true)
	title := boldStyle.Render("Controller IP Address")
	m.remoteAddr.Placeholder = "10.0.0.1:49152"
	m.remoteAddr.CharLimit = 21
	m.remoteAddr.Width = 30
	m.remoteAddr.Prompt = ""
	m.remoteAddr.Focus()
	content := m.remoteAddr.View()
	layout := lipgloss.JoinVertical(lipgloss.Left, title, content)

	return foreStyle.Render(layout)
}

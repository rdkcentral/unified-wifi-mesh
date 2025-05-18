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
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/davecgh/go-spew/spew"
)

// Model implements tea.Model, and manages the browser UI.
type MeshSettings struct {
	windowWidth  int
	windowHeight int
	remoteAddr	textinput.Model
	dump	*os.File
}

func newMeshSettings(platform string, dump *os.File) *MeshSettings {
	remoteAddr := textinput.New()

    return &MeshSettings {
		remoteAddr:		remoteAddr,	
		dump:			dump,
	}
}

// Validator of Remote Controller IP Address
func remoteAddrValidator(addrPort string) bool {
	return false
}

// Init initialises the Model on program load. It partly implements the tea.Model interface.
func (m *MeshSettings) Init() tea.Cmd {
	spew.Fprintf(m.dump, "Mesh Settings Init\n")
	m.remoteAddr.Placeholder = "10.0.0.1:49152"
	m.remoteAddr.CharLimit = 21
	m.remoteAddr.Width = 30
	m.remoteAddr.Prompt = ""
	m.remoteAddr.Focus()

	return textinput.Blink
}

// Update handles event and manages internal state. It partly implements the tea.Model interface.
func (m *MeshSettings) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	spew.Fprintf(m.dump, "Mesh Settings View\n")
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
			case "enter":
				spew.Fprintf(m.dump, "Remote Addr: %s\n", m.remoteAddr.Value())
				if (remoteAddrValidator(m.remoteAddr.Value()) == false) {
					return m, nil
				}
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
	content := m.remoteAddr.View()
	layout := lipgloss.JoinVertical(lipgloss.Left, title, content)

	return foreStyle.Render(layout)
}

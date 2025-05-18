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
	"time"
	"github.com/davecgh/go-spew/spew"
	tea "github.com/charmbracelet/bubbletea"
	overlay "github.com/rmhubbert/bubbletea-overlay"
)

type sessionState int

const (
	meshView sessionState = iota
	settingsView
)

// MeshViewsMgr implements tea.Model, and manages the browser UI.
type MeshViewsMgr struct {
	state        		sessionState
	windowWidth  		int
	windowHeight 		int
	meshSettings   		tea.Model
	meshViews   		tea.Model
	overlay      		tea.Model
	dump           		*os.File
    ticker            	*time.Ticker
	quit		chan bool
	initialized			bool
}

func (m *MeshViewsMgr) timerHandler() {
	if m.initialized == false {
		return
	}

    for {
        select {
        case <-m.ticker.C:
            if program != nil {
                program.Send(refreshUIMsg{})
            }

        case <-m.quit:
            m.ticker.Stop()
            return
        }
    }
}

func newMeshViewsMgr(platform string) *MeshViewsMgr {

	dump, _ := os.OpenFile("messages.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	C.init_lib_dbg(C.CString("messages_lib.log"))

	meshSettings := newMeshSettings(platform, dump)
	meshViews := newMeshViews(platform, dump)

	return &MeshViewsMgr {
		meshSettings:			meshSettings,
		meshViews: 		meshViews,
		initialized:	false,
		dump:	dump,
	}	
}

// Init initialises the MeshViewsMgr on program load. It partly implements the tea.Model interface.
func (m *MeshViewsMgr) Init() tea.Cmd {
	m.state = meshView
	m.overlay = overlay.New(
		m.meshSettings,
		m.meshViews,
		overlay.Center,
		overlay.Center,
		0,
		0,
	)

    m.ticker = time.NewTicker(5 * time.Second)
    m.quit = make(chan bool)

	go m.timerHandler()

	return nil
}

// Update handles event and manages internal state. It partly implements the tea.Model interface.
func (m *MeshViewsMgr) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit

		case "enter":
			if m.state == settingsView {
				m.state = meshView
			}

		case " ":
			if m.state == meshView {
				m.state = settingsView
			}
		}
	}

	fg, fgCmd := m.meshSettings.Update(message)
	m.meshSettings = fg

	bg, bgCmd := m.meshViews.Update(message)
	m.meshViews = bg
	
	cmds := []tea.Cmd{}
	cmds = append(cmds, fgCmd, bgCmd)

	return m, tea.Batch(cmds...)
}

// View applies and styling and handles rendering the view. It partly implements the tea.Model
// interface.
func (m *MeshViewsMgr) View() string {
	spew.Fprintf(m.dump, "Mesh Manager View, state: %d\n", m.state)
	if m.state == settingsView {
		return m.overlay.View()
	}
	return m.meshViews.View()
}

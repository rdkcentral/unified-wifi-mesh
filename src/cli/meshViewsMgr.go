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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/davecgh/go-spew/spew"
)

type sessionState int

const (
	meshView sessionState = iota
	settingsView
)

// MeshViewsMgr implements tea.Model, and manages the browser UI.
type MeshViewsMgr struct {
	//state        sessionState
	windowWidth  int
	windowHeight int
	//meshSettings tea.Model
	meshViews tea.Model
	//overlay     tea.Model
	dump        *os.File
	ticker      *time.Ticker
	quit        chan bool
	timerActive bool
}

func newMeshSettings1(platform string, dump *os.File) {
	// IP: 127.0.0.1 = 0x7F000001 in BE, but little-endian requires shifting like this:
	ip := (127 << 0) | (0 << 8) | (0 << 16) | (1 << 24)
	port := 49153

	C.set_remote_addr(C.uint(ip), C.uint(port), C.bool(true))
}

func (m *MeshViewsMgr) timerHandler() {
	for {
		select {
		case <-m.ticker.C:
			if program != nil {
				program.Send(refreshUIMsg{})
				program.Send(DebugTest{})
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

	//meshSettings := newMeshSettings(platform, dump)
	newMeshSettings1(platform, dump)
	meshViews := newMeshViews(platform, dump)

	mgr := &MeshViewsMgr{
		meshViews:   meshViews,
		timerActive: false,
		dump:        dump,
	}

	// Always enable timer since IP is always valid
	mgr.ActivateTimer(true)

	return mgr
}

func (m *MeshViewsMgr) ActivateTimer(enable bool) {
	if m.timerActive == false && enable == true {
		spew.Fprintf(m.dump, "Starting timer because remote IP is valid\n")
		m.ticker = time.NewTicker(5 * time.Second)
		m.timerActive = true
		go m.timerHandler()
	} else if m.timerActive == true && enable == false {
		spew.Fprintf(m.dump, "Stopping timer because remote IP is invalid\n")
		m.ticker.Stop()
		m.timerActive = false
	}
}

// Init initialises the MeshViewsMgr on program load. It partly implements the tea.Model interface.
func (m *MeshViewsMgr) Init() tea.Cmd {
	/*m.state = meshView
	m.overlay = overlay.New(
		m.meshSettings,
		m.meshViews,
		overlay.Center,
		overlay.Center,
		0,
		0,
	)

	m.quit = make(chan bool)
	*/
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

			/*case "enter":
				if m.state == settingsView {
					m.state = meshView
				}

			case " ":
				if m.state == meshView {
					m.state = settingsView
				}*/
		}
	}

	/*fg, fgCmd := m.meshSettings.Update(message)
	m.meshSettings = fg

	if C.is_remote_addr_valid() == true {
		m.ActivateTimer(true)
	} else {
		m.ActivateTimer(false)

	}*/

	bg, bgCmd := m.meshViews.Update(message)
	m.meshViews = bg

	/*cmds := []tea.Cmd{}
	cmds = append(cmds, fgCmd, bgCmd)

	return m, tea.Batch(cmds...)*/
	return bg, bgCmd
}

// View applies and styling and handles rendering the view. It partly implements the tea.Model
// interface.
/*func (m *MeshViewsMgr) View() string {
	if m.state == settingsView {
		return m.overlay.View()
	}
	return m.meshViews.View()
}*/
func (m *MeshViewsMgr) View() string {
	return m.meshViews.View()
}

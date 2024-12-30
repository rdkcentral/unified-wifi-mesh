package main

import (
	"os"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"etree"
	"golang.org/x/term"
	//"github.com/davecgh/go-spew/spew"
)

var (
	styleDoc = lipgloss.NewStyle().Padding(1)
)

func main() {
	err := tea.NewProgram(newModel()).Start()
	if err != nil {
		os.Exit(1)
	}
}

func newModel() model {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w = 80
		h = 24
	}
	top, right, bottom, left := styleDoc.GetPadding()
	w = w - left - right
	h = h - top - bottom
	
	nodes := make([]etree.Node, 1)

	nodes[0].Key = ""
	nodes[0].Vector = true;
	nodes[0].Children = make([]etree.Node, 1)

    nodes[0].Children[0].Key = "NetworkSSIDList"
	nodes[0].Children[0].Vector = true;
    nodes[0].Children[0].Children = make([]etree.Node, 1)

    nodes[0].Children[0].Children[0].Key = ""
	nodes[0].Children[0].Children[0].Vector = true;
    nodes[0].Children[0].Children[0].Children = make([]etree.Node, 1)

    nodes[0].Children[0].Children[0].Children[0].Key = "SSID"
	nodes[0].Children[0].Children[0].Children[0].Vector = false;
    nodes[0].Children[0].Children[0].Children[0].Value = textinput.New()
    nodes[0].Children[0].Children[0].Children[0].Value.Placeholder = "value"
    nodes[0].Children[0].Children[0].Children[0].Children = nil
	
	dump, _ := os.OpenFile("messages.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)

	return model{tree: etree.New(nodes, false, w, h, dump),
		dump: dump,
	}
}

type model struct {
	tree etree.Model
	dump    *os.File
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.tree, cmd = m.tree.Update(msg)

	return m, cmd
}

func (m model) View() string {
	return styleDoc.Render(m.tree.View())
}

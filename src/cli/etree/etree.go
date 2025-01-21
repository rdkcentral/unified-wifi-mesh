package etree

import (
    "fmt"
    "os"
    "strings"
    "github.com/charmbracelet/bubbles/textinput"
    "github.com/charmbracelet/bubbles/help"
    "github.com/charmbracelet/bubbles/key"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
	"github.com/davecgh/go-spew/spew"
)


const (
    scalarPrefix string = "  └──"
    vectorCollapsedPrefix string = "  [+] "
    vectorExpandedPrefix string = "  [─] "

    white  = lipgloss.Color("#ffffff")
    black  = lipgloss.Color("#000000")
    purple = lipgloss.Color("#bd93f9")
    lightGrey = lipgloss.Color("#d3d3d3")
	
	NodeTypeInvalid = 0
	NodeTypeFalse = 1
	NodeTypeTrue = 2
	NodeTypeNull = 3
	NodeTypeNumber = 4
	NodeTypeString = 5
	NodeTypeObject = 6
	NodeTypeArrayObj = 7
	NodeTypeArrayStr = 8
	NodeTypeArrayNum = 9
	NodeTypeRaw = 10
)


type Styles struct {
    Shapes     lipgloss.Style
    Selected   lipgloss.Style
    Unselected lipgloss.Style
    Help       lipgloss.Style
}

func defaultStyles() Styles {
    return Styles{
        Shapes:     lipgloss.NewStyle().Margin(0, 0, 0, 0).Foreground(black),
        Selected:   lipgloss.NewStyle().Margin(0, 0, 0, 0).Background(lightGrey),
        //Unselected: lipgloss.NewStyle().Margin(0, 0, 0, 0).Foreground(lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"}),
        Help:       lipgloss.NewStyle().Margin(0, 0, 0, 0).Foreground(lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"}),
    }
}

type Node struct {
    Key    string
	Type	int
	Collapsed	bool
    Value    textinput.Model
    Children []Node
}

type Model struct {
    KeyMap KeyMap
    Styles Styles

    width  int
    height int
    nodes  []Node
    cursor int
	editable	bool

    Help     help.Model
    showHelp bool
	dump    *os.File

    AdditionalShortHelpKeys func() []key.Binding
}

func New(nodes []Node, editable bool, width int, height int, dump *os.File) Model {
    return Model{
        KeyMap: DefaultKeyMap(),
        Styles: defaultStyles(),

        width:  width,
        height: height,
		
		editable: editable,
        nodes:  nodes,

        showHelp: true,
		dump: dump,
        Help:     help.New(),
    }
}

// KeyMap holds the key bindings for the table.
type KeyMap struct {
    Bottom      key.Binding
    Top         key.Binding
    SectionDown key.Binding
    SectionUp   key.Binding
    Down        key.Binding
    Up          key.Binding
    Quit        key.Binding

    ShowFullHelp  key.Binding
    CloseFullHelp key.Binding
}


// DefaultKeyMap is the default key bindings for the table.
func DefaultKeyMap() KeyMap {
    return KeyMap{
        Bottom: key.NewBinding(
            key.WithKeys("bottom"),
            key.WithHelp("end", "bottom"),
        ),
        Top: key.NewBinding(
            key.WithKeys("top"),
            key.WithHelp("home", "top"),
        ),
        SectionDown: key.NewBinding(
            key.WithKeys("secdown"),
            key.WithHelp("secdown", "section down"),
        ),
        SectionUp: key.NewBinding(
            key.WithKeys("secup"),
            key.WithHelp("secup", "section up"),
        ),
        Down: key.NewBinding(
            key.WithKeys("down"),
            key.WithHelp("↓", "down"),
        ),
        Up: key.NewBinding(
            key.WithKeys("up"),
            key.WithHelp("↑", "up"),
        ),
        ShowFullHelp: key.NewBinding(
            key.WithKeys("?"),
            key.WithHelp("?", "more"),
        ),
        CloseFullHelp: key.NewBinding(
            key.WithKeys("?"),
            key.WithHelp("?", "close help"),
        ),

        Quit: key.NewBinding(
            key.WithKeys("q", "esc"),
            key.WithHelp("q", "quit"),
        ),
    }
}

func isNodeVector(node *Node) bool {
	if node.Type == NodeTypeObject || node.Type == NodeTypeArrayObj {
		return true
	}

	return false
}

func (m Model) Nodes() []Node {
    return m.nodes
}

func (m *Model) SetNodes(nodes []Node) {
	spew.Fdump(m.dump, "Nodes Set")
    m.nodes = nodes
}

func (m *Model) NumberOfNodes() int {
    count := 0

    var countNodes func([]Node)
    countNodes = func(nodes []Node) {
        for _, node := range nodes {
            count++
            if node.Children != nil {
                countNodes(node.Children)
            }
        }
    }

    countNodes(m.nodes)

    return count

}

func (m Model) Width() int {
    return m.width
}

func (m Model) Height() int {
    return m.height
}

func (m *Model) SetSize(width, height int) {
    m.width = width
    m.height = height
}

func (m *Model) SetWidth(newWidth int) {
    m.SetSize(newWidth, m.height)
}

func (m *Model) SetHeight(newHeight int) {
    m.SetSize(m.width, newHeight)
}

func (m Model) Cursor() int {
    return m.cursor
}

func (m *Model) SetCursor(cursor int) {
    m.cursor = cursor
}

func (m Model) Editable() bool {
    return m.editable
}

func (m *Model) SetEditable(editable bool) {
    m.editable = editable
}

func (m *Model) SetShowHelp() bool {
    return m.showHelp
}

func (m *Model) NavUp() {
    m.cursor--

    if m.cursor < 0 {
        m.cursor = 0
        return
    }

}

func (m *Model) NavDown() {
    m.cursor++

    if m.cursor >= m.NumberOfNodes() {
        m.cursor = m.NumberOfNodes() - 1
        return
    }
}

func (m Model) NodeAtCursor(remainingNodes []Node, count *int) *Node {

    for i, node := range remainingNodes {

        idx := *count
        *count++

        if idx == m.cursor {
            return &remainingNodes[i]
        }

        if node.Children != nil {
			// assuming that the algorithm will always have to return a non nil value eventually
			var res *Node
            res = m.NodeAtCursor(node.Children, count)
			if res != nil {
				return res
			}
        }
    }

    return nil
}

func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch {
        case key.Matches(msg, m.KeyMap.Up):
            m.NavUp()
        case key.Matches(msg, m.KeyMap.Down):
            m.NavDown()
        case key.Matches(msg, m.KeyMap.ShowFullHelp):
            fallthrough
        case key.Matches(msg, m.KeyMap.CloseFullHelp):
            m.Help.ShowAll = !m.Help.ShowAll
        }
    }

    count := 0
    node := m.NodeAtCursor(m.nodes, &count)
	if m.editable == true && node != nil && isNodeVector(node) == false {
    	var cmd tea.Cmd
   		node.Value.Focus()
   		node.Value, cmd = node.Value.Update(msg)
		return m, cmd
    
	}
		
	return m, nil

}

func (m Model) TreeView() string {
    count := 0
	if len(m.nodes) == 0 {
		return "OneWifiMesh is an EasyMesh based stack that allows implementing a WiFi Network"
	}
	return m.renderTree(m.nodes, 1, &count)
}

func (m Model) View() string {
    availableHeight := m.height
    var sections []string

    nodes := m.Nodes()
    var help string
    if m.showHelp {
        help = m.helpView()
        availableHeight -= lipgloss.Height(help)
    }
    count := 0 // This is used to keep track of the index of the node we are on (important because we are using a recursive function)
    sections = append(sections, lipgloss.NewStyle().Height(availableHeight).Render(m.renderTree(m.nodes, 1, &count)), help)
    if len(nodes) == 0 {
        return "No data"
    }
    return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m *Model) renderTree(remainingNodes []Node, indent int, count *int) string {
    var b strings.Builder

    for _, node := range remainingNodes {

        var str string
		var prefix string

		if isNodeVector(&node) == false {
			prefix = scalarPrefix
		} else {
			if node.Collapsed == true {
				prefix = vectorCollapsedPrefix
			} else {
				prefix = vectorExpandedPrefix
			}
		}

        // If we aren't at the root, we add the arrow shape to the string
        if indent > 0 {
            shape := strings.Repeat(" ", (indent-1)*2) + m.Styles.Shapes.Render(prefix) + " "
            str += shape
        }

        // Generate the correct index for the node
        idx := *count
        *count++

        // Format the string with fixed width for the value and description fields
        keyWidth := 10
        valWidth := 20
        keyStr := fmt.Sprintf("%-*s", keyWidth, node.Key)
		valStr := ""
		if isNodeVector(&node) == false {
        	valStr = fmt.Sprintf("%-*s", valWidth, node.Value.View())
		}

        // If we are at the cursor, we add the selected style to the string
        if m.cursor == idx {
            str += fmt.Sprintf("%s\t\t%s\n", m.Styles.Selected.Render(keyStr), m.Styles.Selected.Render(valStr))
        } else {
            str += fmt.Sprintf("%s\t\t%s\n", m.Styles.Unselected.Render(keyStr), m.Styles.Unselected.Render(valStr))
        }

        b.WriteString(str)

        if node.Children != nil {
            childStr := m.renderTree(node.Children, indent+1, count)
            b.WriteString(childStr)
        }
    }

    return b.String()
}

func (m Model) helpView() string {
    return m.Styles.Help.Render(m.Help.View(m))
}

func (m Model) ShortHelp() []key.Binding {
    kb := []key.Binding{
        m.KeyMap.Up,
        m.KeyMap.Down,
    }

    if m.AdditionalShortHelpKeys != nil {
        kb = append(kb, m.AdditionalShortHelpKeys()...)
    }

    return append(kb,
        m.KeyMap.Quit,
    )
}

func (m Model) FullHelp() [][]key.Binding {
    kb := [][]key.Binding{{
        m.KeyMap.Up,
        m.KeyMap.Down,
    }}

    return append(kb,
        []key.Binding{
            m.KeyMap.Quit,
            m.KeyMap.CloseFullHelp,
        })
}


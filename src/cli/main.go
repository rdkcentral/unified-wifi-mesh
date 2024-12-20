package main

/*
#cgo CFLAGS: -I../../inc -I../../../OneWifi/include -I../../../OneWifi/source/utils -I../../../halinterface/include
#cgo LDFLAGS: -L../../install/lib -lemcli -lcjson
#include "em_cli_apis.h"
*/
import "C"
import (
    "fmt"
    "os"
    "strings"

    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/bubbles/list"
    tree "github.com/savannahostrowski/tree-bubble"
)

var (
    appStyle = lipgloss.NewStyle().Padding(1, 2)

    titleStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("#080563")).
        Padding(1, 8).
        Bold(true)

    menuBorderStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("#C1E5FB")).
        Width(30)

    statusBorderStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("#79B4D7")).
        Height(48)

    jsonStyle = lipgloss.NewStyle().
        Border(lipgloss.RoundedBorder()).
        BorderForeground(lipgloss.Color("#080563")).
        Background(lipgloss.Color("#FFFFFF")).
        Foreground(lipgloss.Color("#000000")).
        Width(95).
        Padding(0, 10).
        MarginLeft(10).
        MarginTop(2)

    buttonStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("#FFFFFF")).
        Background(lipgloss.Color("#080563")).
        Padding(0, 2).
        Width(25).
        Align(lipgloss.Center)

    activeButtonStyle = buttonStyle.Copy().
        Background(lipgloss.Color("39")).
        Bold(true)

    activeNodeStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("39")).
        Foreground(lipgloss.Color("black")).
        Bold(true)
)

type item struct {
    title    string
    isActive bool
}

func (i item) Title() string {
    if i.isActive {
        return activeButtonStyle.Render(i.title)
    }
    return buttonStyle.Render(i.title)
}

func (i item) Description() string { return "" }
func (i item) FilterValue() string { return i.title }

var commandDescriptions = map[string]string{
    "Set SSID":               "set_ssid allows you to configure the SSID.",
    "Show Devices":           "You have pressed get_device option.",
    "Remove Device":          "remove_device command is used to remove a device.",
    "Show Radios":            "get_radio command shows radio details.",
    "Disable Radio":          "disable radio.",
    "Show Current Channels":  "get_channel fetches the channel information.",
    "Set Channel":            "set_channel sets the wireless channel.",
    "Show Networks":          "show_networks displays the networks.",
    "Steer Clients":          "steer_sta steers a station to a different AP.",
    "Disassociate Clients":   "disassoc_sta disassociates a station.",
}

type model struct {
    list          list.Model
    statusMessage string
    scrollContent []string
    scrollIndex   int
    activeButton  int
    currentNode   *tree.Node
    cursor int
}

func newModel() model {
    items := []list.Item{
        item{title: "Set SSID"},
        item{title: "Show Devices"},
        item{title: "Remove Device"},
        item{title: "Show Radios"},
        item{title: "Disable Radio"},
        item{title: "Show Current Channels"},
        item{title: "Set Channel"},
        item{title: "Show Networks"},
        item{title: "Steer Clients"},
        item{title: "Disassociate Clients"},
    }

    commandList := list.New(items, list.NewDefaultDelegate(), 0, 0)
    commandList.Title = "OneWifiMesh"
    commandList.Styles.Title = titleStyle
    commandList.SetShowStatusBar(false)
    commandList.SetShowPagination(false)
    commandList.SetShowHelp(false)

    return model{
        list:          commandList,
        statusMessage: "",
    }
}

func splitIntoLines(content string) []string {
    return strings.Split(content, "\n")
}

func (m model) Init() tea.Cmd {
    return nil
}

func updateNodes(netNode *C.em_network_node_t, treeNode *tree.Node) {
    var str *C.char

    treeNode.Value = C.GoString(&netNode.key[0])
    nodeType := C.get_node_type(netNode)

    if nodeType == C.em_network_node_data_type_array {
        if int(netNode.num_children) > 0 {
            childNetNode := C.get_child_node_at_index(netNode, 0);
            childNodeType := C.get_node_type(childNetNode)
            if ((childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
                    (childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true)) {
                str = C.get_formatted_node_array_value(netNode)
                treeNode.Desc = C.GoString(str)
                C.free_formatted_node_value(str)
            } else {
                treeNode.Children = make([]tree.Node, uint(netNode.num_children))
                for i := 0; i < int(netNode.num_children); i++ {
                    childNetNode := C.get_child_node_at_index(netNode, C.uint(i));
                    childTreeNode := &treeNode.Children[i]
                    updateNodes(childNetNode, childTreeNode)
                }
            }
        }

    } else if ((nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
            (nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true)) {
        str = C.get_formatted_node_scalar_value(netNode)
        treeNode.Desc = C.GoString(str)
        C.free_formatted_node_value(str)
    } else {
        treeNode.Children = make([]tree.Node, uint(netNode.num_children))
        for i := 0; i < int(netNode.num_children); i++ {
            childNetNode := C.get_child_node_at_index(netNode, C.uint(i));
            childTreeNode := &treeNode.Children[i]
            updateNodes(childNetNode, childTreeNode)
        }
    }
}

func formatTree(nodes []tree.Node, m *model, cursor *int, currentIdx *int) string {
    var builder strings.Builder

    var traverse func(node tree.Node, indent string)
    traverse = func(node tree.Node, indent string) {
        // Create a prefix for child nodes
        prefix := "├── "
        if len(node.Children) == 0 {
            prefix = "└── "
        }

        // Generate the current index and increment for each node
        idx := *currentIdx
        *currentIdx++

        // Style node based on selection state
        var line string
        if *cursor == idx {
            line = fmt.Sprintf("%s%s%s : %s", indent, prefix, activeNodeStyle.Render(node.Value), activeNodeStyle.Render(node.Desc))
        } else {
            line = fmt.Sprintf("%s%s%s : %s", indent, prefix, node.Value, node.Desc)
        }

        builder.WriteString(line + "\n")

        // Traverse the children with increased indentation
        for _, child := range node.Children {
            traverse(child, indent+"    ")
        }
    }

    // Start traversal
    //traverse(node, "")
    for _, node := range nodes {
        traverse(node, "")
    }
    return builder.String()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        h, _ := appStyle.GetFrameSize()
        menuHeight := 45
        m.list.SetSize(msg.Width-h, menuHeight)

    case tea.KeyMsg:
        switch msg.String() {
        case "tab":
            m.activeButton = (m.activeButton + 1) % 2
        case "enter":
            if m.activeButton == 0 && len(m.scrollContent) > 0 {
                m.statusMessage = "OK Button Pressed"
            } else if m.activeButton == 1 {
                m.statusMessage = "Cancel Button Pressed"
            } else if selectedItem, ok := m.list.SelectedItem().(item); ok {
                if selectedItem.title == "Set SSID" {
                    node := C.get_network_tree_by_file(C.CString("NetworkSSID.json"))
                    if node == nil {
                        m.statusMessage = "Error: Failed to retrieve network tree."
                        m.scrollContent = nil
                    } else {
                        defer C.free_network_tree(node)

                        treeNode := make([]tree.Node, 1)
                        updateNodes(node, &treeNode[0])

                        m.currentNode = &treeNode[0]
                        currentIdx := 0
                        cursor := 0
                        content := formatTree(treeNode, &m, &cursor, &currentIdx)
                        m.scrollContent = splitIntoLines(content)
                        m.scrollIndex = 0
                    }
                } else if description, found := commandDescriptions[selectedItem.title]; found {
                    m.statusMessage = description
                    m.scrollContent = nil
                } else {
                    m.statusMessage = "No command available for this option."
                    m.scrollContent = nil
                }

            }
        case "w":
            if m.scrollIndex > 0 {
                m.scrollIndex--
            }
        case "s":
            if m.scrollIndex < len(m.scrollContent)-1 {
                m.scrollIndex++
            }
        default:
            newListModel, cmd := m.list.Update(msg)
            m.list = newListModel
            for i := range m.list.Items() {
                if listItem, ok := m.list.Items()[i].(item); ok {
                    listItem.isActive = i == m.list.Index()
                    m.list.SetItem(i, listItem)
                }
            }
            cmds = append(cmds, cmd)
        }
    }
    return m, tea.Batch(cmds...)
}

func (m model) View() string {
    menuView := m.list.View()

    instructions := lipgloss.NewStyle().
        Foreground(lipgloss.Color("#000000")).
        Background(lipgloss.Color("#C1E5FB")).
        Padding(1, 2).
        Render("↑/k up ● ↓/j down ● q quit")

    menuViewWithInstructions := lipgloss.JoinVertical(lipgloss.Left, menuView, instructions)

    var statusView string
    if len(m.scrollContent) > 0 {
        const linesToDisplay = 38
        end := m.scrollIndex + linesToDisplay
        if end > len(m.scrollContent) {
            end = len(m.scrollContent)
        }
        styledContent := jsonStyle.Render(strings.Join(m.scrollContent[m.scrollIndex:end], "\n"))

        statusView = styledContent + "\n\n\t Press 'w' to scroll up, 's' to scroll down"
    } else {
        statusView = m.statusMessage
    }

    okButton := buttonStyle.Render("OK")
    cancelButton := buttonStyle.Render("Cancel")
    if m.activeButton == 0 {
        okButton = activeButtonStyle.Render("OK")
    } else {
        cancelButton = activeButtonStyle.Render("Cancel")
    }

    buttons := lipgloss.JoinHorizontal(lipgloss.Center, okButton, cancelButton)
    centeredButtons := lipgloss.NewStyle().Width(100).Align(lipgloss.Center).Render(buttons)
    statusView = statusView + "\n\n" + centeredButtons

    combinedView := lipgloss.JoinHorizontal(
        lipgloss.Top,
        menuBorderStyle.Render(menuViewWithInstructions),
        statusBorderStyle.Width(120).Render(statusView),
    )

    commonBorderStyle := lipgloss.NewStyle().
        Border(lipgloss.RoundedBorder()).
        BorderForeground(lipgloss.Color("#080563")).
        Padding(0).
        Bold(true)

    return commonBorderStyle.Render(combinedView)
}

func main() {
    if _, err := tea.NewProgram(newModel(), tea.WithAltScreen()).Run(); err != nil {
        fmt.Println("Error running program:", err)
        os.Exit(1)
    }
}

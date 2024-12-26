package main

/*
#cgo CFLAGS: -I../../inc -I../../../OneWifi/include -I../../../OneWifi/source/utils -I../../../halinterface/include
#cgo LDFLAGS: -L../../install/lib -lemcli -lcjson -lreadline
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "em_cli_apis.h"

extern int editor_func(em_network_node_t *node);

static int register_editor_cb() {
	return init(editor_func, NULL);
}
*/
import "C"

import (
	"fmt"
	"os"
    "strings"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/bubbles/list"
    "github.com/davecgh/go-spew/spew"
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

    listItemStyle = lipgloss.NewStyle().
    Foreground(lipgloss.Color("#FFFFFF")).
    Background(lipgloss.Color("#080563")). 
    Width(25).
    Align(lipgloss.Center) 

    buttonStyle = lipgloss.NewStyle().
    Foreground(lipgloss.Color("#FFFFFF")).
    Background(lipgloss.Color("#080563")).
    Padding(0, 1).
    MarginRight(3).
    Width(25).
    Align(lipgloss.Center).
    MarginBackground(lipgloss.Color("#79B4D7"))

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
    return listItemStyle.Render(i.title)
}

func (i item) Description() string { return "" }
func (i item) FilterValue() string { return i.title }

var commandDescriptions = map[string]string{
    "Network SSID List":               "allows you to configure the SSID.",
    "Network Tree":                    "You have pressed Network Tree option.",
    "Radios":                          "Radio details.",
    "Channels":                        "Display channel details.",
    "Client Devices":                  "Fetches the client information.",
}

type model struct {
    list          list.Model
    statusMessage string
    scrollContent []string
    scrollIndex   int
    activeButton  int
    currentTreeNode   *tree.Node
    currentNetNode   *C.em_network_node_t
    displayedNetNode   *C.em_network_node_t
    cursor int
    dump 	*os.File
    collapsedState    map[string]bool
}

func newModel() model {
    items := []list.Item{
        item{title: "Network SSID List"},
        item{title: "Network Tree"},
        item{title: "Radios"},
        item{title: "Channels"},
        item{title: "Client Devices"},
    }

    commandList := list.New(items, list.NewDefaultDelegate(), 0, 0)
    commandList.Title = "OneWifiMesh"
    commandList.Styles.Title = titleStyle
    commandList.SetShowStatusBar(false)
    commandList.SetShowPagination(false)
    commandList.SetShowHelp(false)

    dump, _ := os.OpenFile("messages.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
    C.init_lib_dbg(C.CString("messages_lib.log"))

    return model{
        list:          commandList,
        statusMessage: "",
        dump: dump,
        collapsedState: make(map[string]bool),
    }
}

func splitIntoLines(content string) []string {
    return strings.Split(content, "\n")
}

func (m model) Init() tea.Cmd {
    return nil
}

//export editor_func
func editor_func(*C.em_network_node_t) C.int {
    fmt.Println("Inside Go Callnack")
    return 0
}

func updateNodes(netNode *C.em_network_node_t, treeNode *tree.Node) {
    var str *C.char

    //treeNode.Value = C.GoString(&netNode.key[0]) + "." + fmt.Sprintf("%d", uint(netNode.display_info.node_ctr)) + "." + fmt.Sprintf("%d", uint(netNode.display_info.orig_node_ctr))
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

        uniqueID := fmt.Sprintf("%s_%d", node.Value, *currentIdx)
        isCollapsed := m.collapsedState[uniqueID]

        prefix := "[+]"
        if !isCollapsed {
            prefix = "[-]"
        }

        idx := *currentIdx
        *currentIdx++

        var line string
        if *cursor == idx {
            line = fmt.Sprintf("%s%s%s  %s", indent, prefix, activeNodeStyle.Render(node.Value), activeNodeStyle.Render(node.Desc))
        } else {
            line = fmt.Sprintf("%s%s%s  %s", indent, prefix, node.Value, node.Desc)
        }

        builder.WriteString(line + "\n")

        if !isCollapsed {
            for _, child := range node.Children {
                traverse(child, indent+"    ")
            }
        }
    }

    for _, node := range nodes {
        traverse(node, "")
    }
    return builder.String()
}


func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd
    const linesToDisplay = 38

    if m.dump != nil {
        spew.Fdump(m.dump, msg)
    }

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        h, _ := appStyle.GetFrameSize()
        menuHeight := 45
        m.list.SetSize(msg.Width-h, menuHeight)

    case tea.KeyMsg:
        switch msg.String() {
        case "tab":
            m.activeButton = (m.activeButton + 1) % 3

        case "enter":
            if m.activeButton == 0 && len(m.scrollContent) > 0 {
                m.statusMessage = "OK Button Pressed"
            } else if m.activeButton == 1 {
                m.statusMessage = "Cancel Button Pressed"
            } else if selectedItem, ok := m.list.SelectedItem().(item); ok {
                if selectedItem.title == "Network SSID List" {
                    m.currentNetNode = C.get_network_tree_by_file(C.CString("NetworkSSID.json"))
                    if m.currentNetNode == nil {
                        m.statusMessage = "Error: Failed to retrieve network tree."
                        m.scrollContent = nil
                    } else {
                        treeNode := make([]tree.Node, 1)
                        m.currentTreeNode = &treeNode[0]
                        m.displayedNetNode = C.clone_network_tree(m.currentNetNode, nil, 0xffff, false)
                        updateNodes(m.displayedNetNode, m.currentTreeNode)

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
            if m.cursor > 0 {
                m.cursor--
                if m.cursor < m.scrollIndex {
                    m.scrollIndex--
                }
                updateScrollContent(&m)
            }

        case "s":
            if m.cursor < len(m.scrollContent)-1 {
                m.cursor++
                if m.cursor >= m.scrollIndex+linesToDisplay {
                    m.scrollIndex++
                }
                updateScrollContent(&m)
            }

        case "c":
            netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.cursor))
            if uint(C.can_collapse_node(netNode)) == 1 {
                uniqueID := fmt.Sprintf("%s_%d", C.GoString(&netNode.key[0]), m.cursor) 
                m.collapsedState[uniqueID] = true 

                tmp := m.displayedNetNode
                m.displayedNetNode = C.clone_network_tree(m.currentNetNode, m.displayedNetNode, C.uint(m.cursor), true)
                defer C.free_network_tree(tmp);
                str := C.get_network_tree_string(m.displayedNetNode)
                spew.Fdump(m.dump, "Collapse", m.cursor)
                C.dump_lib_dbg(str)

                treeNode := make([]tree.Node, 1)
                m.currentTreeNode = &treeNode[0]
                updateNodes(m.displayedNetNode, m.currentTreeNode)

                currentIdx := 0
                cursor := 0
                content := formatTree(treeNode, &m, &cursor, &currentIdx)
                m.scrollContent = splitIntoLines(content)
                m.scrollIndex = 0
            }

        case "e":
            netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.cursor))
            if (uint(C.can_expand_node(netNode))) == 1 {
                uniqueID := fmt.Sprintf("%s_%d", C.GoString(&netNode.key[0]), m.cursor)  
                m.collapsedState[uniqueID] = false

                tmp := m.displayedNetNode
                m.displayedNetNode = C.clone_network_tree(m.currentNetNode, m.displayedNetNode, C.uint(m.cursor), false)
                defer C.free_network_tree(tmp);

                str := C.get_network_tree_string(m.displayedNetNode)
                spew.Fdump(m.dump, "Expand", m.cursor)
                C.dump_lib_dbg(str)

                treeNode := make([]tree.Node, 1)
                m.currentTreeNode = &treeNode[0]
                updateNodes(m.displayedNetNode, m.currentTreeNode)

                currentIdx := 0
                cursor := 0
                content := formatTree(treeNode, &m, &cursor, &currentIdx)
                m.scrollContent = splitIntoLines(content)
                m.scrollIndex = 0
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

func updateScrollContent(m *model) {
    if m.currentTreeNode != nil {
        currentIdx := 0
        content := formatTree([]tree.Node{*m.currentTreeNode}, m, &m.cursor, &currentIdx)
        m.scrollContent = splitIntoLines(content)
    }
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
    
    updateButton := buttonStyle.Render("Update")
    okButton := buttonStyle.Render("OK")
    cancelButton := buttonStyle.Render("Cancel")
    switch m.activeButton {
        case 0:
            updateButton = activeButtonStyle.Render("Update")
        case 1:
            okButton = activeButtonStyle.Render("OK")
        case 2:
            cancelButton = activeButtonStyle.Render("Cancel")
    }

    buttons := lipgloss.JoinHorizontal(lipgloss.Center, updateButton, okButton, cancelButton)
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

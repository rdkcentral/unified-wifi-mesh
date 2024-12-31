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
	"etree"
	"unsafe"
	"fmt"
	"os"
    "strings"
	"github.com/charmbracelet/bubbles/textinput"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/bubbles/list"
	"golang.org/x/term"
    "github.com/davecgh/go-spew/spew"
)

const (
	linesToDisplay int = 38
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
    //BorderForeground(lipgloss.Color("#080563")).
    Background(lipgloss.Color("#FFFFFF")).
    //Foreground(lipgloss.Color("#000000")).
    Width(95).
    //Padding(0, 10).
    //MarginLeft(10).
    MarginTop(2)

    listItemStyle = lipgloss.NewStyle().
    Foreground(lipgloss.Color("#FFFFFF")).
    Background(lipgloss.Color("#080563")). 
    Width(25).
    Align(lipgloss.Center) 

	activeItemStyle = listItemStyle.Copy().
    Background(lipgloss.Color("39")).
    Bold(true)

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

	styleDoc = lipgloss.NewStyle().Padding(1)
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
	currentOperatingInstructions	string
    scrollContent []string
    scrollIndex   int
    activeButton  int
    tree   etree.Model
    currentNetNode   *C.em_network_node_t
    displayedNetNode   *C.em_network_node_t
    cursor int
    dump 	*os.File
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

	// etree related
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
    if err != nil {
        w = 80
        h = 24
    }
    top, right, bottom, left := styleDoc.GetPadding()
    w = w - left - right
    h = h - top - bottom

	nodes := make([]etree.Node, 3)

    nodes[0].Key = "Key1"
    nodes[0].Type = etree.NodeTypeObject
    nodes[0].Children = make([]etree.Node, 1)

	nodes[0].Children[0].Key = "Child of Key1"
    nodes[0].Children[0].Type = etree.NodeTypeString
    nodes[0].Children[0].Value = textinput.New()
	nodes[0].Children[0].Value.Placeholder = "Value"
    nodes[0].Children[0].Children = nil


    nodes[1].Key = "Key2"
    nodes[1].Type = etree.NodeTypeObject
    nodes[1].Children = make([]etree.Node, 1)

	nodes[1].Children[0].Key = "Child of Key2"
    nodes[1].Children[0].Type = etree.NodeTypeString 
    nodes[1].Children[0].Value = textinput.New()
	nodes[1].Children[0].Value.Placeholder = "Value"
    nodes[1].Children[0].Children = nil

    nodes[2].Key = "Key3"
    nodes[2].Type = etree.NodeTypeObject
    nodes[2].Children = make([]etree.Node, 1)

	nodes[2].Children[0].Key = "Child of Key3"
    nodes[2].Children[0].Type = etree.NodeTypeString
    nodes[2].Children[0].Value = textinput.New()
	nodes[2].Children[0].Value.Placeholder = "Value"
    nodes[2].Children[0].Children = nil

    dump, _ := os.OpenFile("messages.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
    C.init_lib_dbg(C.CString("messages_lib.log"))

    return model{
        list:          commandList,
        statusMessage: "",
		activeButton: 4,
		tree: etree.New(nodes, false, w, h, dump),
        dump: dump,
    }
}

func splitIntoLines(content string) []string {
    return strings.Split(content, "\n")
}

func (m model) Init() tea.Cmd {
	var params *C.em_cli_params_t

	params = (*C.em_cli_params_t)(C.malloc(C.sizeof_em_cli_params_t))
	
	params.user_data = unsafe.Pointer(&m)
	params.cb_func = nil
	params.cli_type = C.em_cli_type_go
		
	m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"

	C.init(params)

    return textinput.Blink
}

func treeToNodes(treeNode *etree.Node) *C.em_network_node_t {
	netNode := (*C.em_network_node_t)(C.malloc(C.sizeof_em_network_node_t))
	C.memset(unsafe.Pointer(netNode), 0, C.sizeof_em_network_node_t)
	C.strncpy((*C.char)(&netNode.key[0]), C.CString(treeNode.Key), C.ulong(len(treeNode.Key)))

	C.set_node_type(netNode, C.int(treeNode.Type))

	value := treeNode.Value.Value()
	if value == "" {
		value = treeNode.Value.Placeholder
	}

	if treeNode.Type == etree.NodeTypeArrayStr || treeNode.Type == etree.NodeTypeArrayNum {
		C.set_node_array_value(netNode, C.CString(value))
	} else {
		C.set_node_scalar_value(netNode, C.CString(value))
	}

	if treeNode.Children != nil {
		for i := 0; i < len(treeNode.Children); i++ {
			netNode.child[i] = treeToNodes(&treeNode.Children[i])
		}

		netNode.num_children = C.uint(len(treeNode.Children))
	}

	return netNode
}

func nodesToTree(netNode *C.em_network_node_t, treeNode *etree.Node) {
    var str *C.char

    //treeNode.Value = C.GoString(&netNode.key[0]) + "." + fmt.Sprintf("%d", uint(netNode.display_info.node_ctr)) + "." + fmt.Sprintf("%d", uint(netNode.display_info.orig_node_ctr))
    treeNode.Key = C.GoString(&netNode.key[0])
    nodeType := C.get_node_type(netNode)

    if nodeType == C.em_network_node_data_type_array_obj {
        if int(netNode.num_children) > 0 {
            childNetNode := C.get_child_node_at_index(netNode, 0);
            childNodeType := C.get_node_type(childNetNode)
            if ((childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
            		(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true)) {
				var arrNodeType C.em_network_node_data_type_t
                str = C.get_node_array_value(netNode, &arrNodeType)
				treeNode.Value = textinput.New()
                treeNode.Value.Placeholder = C.GoString(str)
				treeNode.Type = int(arrNodeType)
                C.free_node_value(str)
            } else {
                treeNode.Children = make([]etree.Node, uint(netNode.num_children))
				treeNode.Type = int(C.em_network_node_data_type_array_obj)
				if (netNode.display_info.collapsed) {
					treeNode.Collapsed = true
				}
                for i := 0; i < int(netNode.num_children); i++ {
                    childNetNode := C.get_child_node_at_index(netNode, C.uint(i));
                    nodesToTree(childNetNode, &treeNode.Children[i])
                }
            }
        }

    } else if ((nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
    				(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true)) {
        str = C.get_node_scalar_value(netNode)
		treeNode.Type = int(nodeType)
		treeNode.Value = textinput.New()
        treeNode.Value.Placeholder = C.GoString(str)
        C.free_node_value(str)
    } else {
        treeNode.Children = make([]etree.Node, uint(netNode.num_children))
		treeNode.Type = int(nodeType)
		if (netNode.display_info.collapsed) {
			treeNode.Collapsed = true
		}
        for i := 0; i < int(netNode.num_children); i++ {
            childNetNode := C.get_child_node_at_index(netNode, C.uint(i));
            nodesToTree(childNetNode, &treeNode.Children[i])
        }
    }
}

func isNodeScalar(netNode *C.em_network_node_t) bool {
	nodeType := C.get_node_type(netNode)

	if nodeType == C.em_network_node_data_type_false || nodeType == C.em_network_node_data_type_true ||
				nodeType == C.em_network_node_data_type_number || nodeType == C.em_network_node_data_type_string {
		return true
	}

	if nodeType == C.em_network_node_data_type_array_obj && netNode.num_children > 0 {
		child := netNode.child[0]
		nodeType = C.get_node_type(child)
		if nodeType == C.em_network_node_data_type_false || nodeType == C.em_network_node_data_type_true ||
                nodeType == C.em_network_node_data_type_number || nodeType == C.em_network_node_data_type_string {
        	return true
    	}
	}

	return false
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
            m.activeButton = (m.activeButton + 1) % 3

		case "j", "k":
			m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"

			if m.activeButton != 0 {
            	newListModel, cmd := m.list.Update(msg)
            	m.list = newListModel
            	for i := range m.list.Items() {
                	if listItem, ok := m.list.Items()[i].(item); ok {
                    	listItem.isActive = i == m.list.Index()
                    	m.list.SetItem(i, listItem)
                	}
            	}
            	cmds = append(cmds, cmd)

            	if selectedItem, ok := m.list.SelectedItem().(item); ok {
					if selectedItem.title == "Network SSID List" { 
                   		m.currentNetNode = C.exec(C.CString("get_ssid OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
        				spew.Fdump(m.dump, "Nodes Created for SetSSID")
					} else if selectedItem.title == "Radios" {
                   		m.currentNetNode = C.exec(C.CString("get_radio OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
        				spew.Fdump(m.dump, "Radio List")
					} else if selectedItem.title == "Network Tree" {
                   		m.currentNetNode = C.exec(C.CString("get_bss OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
        				spew.Fdump(m.dump, "BSS List")
					} else if selectedItem.title == "Channels" {
                   		m.currentNetNode = C.exec(C.CString("get_channel OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
        				spew.Fdump(m.dump, "Channels List")
					} else if selectedItem.title == "Client Devices" {
                   		m.currentNetNode = C.exec(C.CString("get_sta OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
        				spew.Fdump(m.dump, "Clients List")
					} 
						
					treeNode := make([]etree.Node, 1)
    				m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
    				nodesToTree(m.displayedNetNode, &treeNode[0])
					m.tree.SetNodes(treeNode)
				}
			}
/*
        case "down":
            if m.cursor > 0 {
                m.cursor--
                if m.cursor < m.scrollIndex {
                    m.scrollIndex--
                }
            }
        
        case "up":
            if m.cursor < len(m.scrollContent) - 1 {
                m.cursor++
                if m.cursor >= m.scrollIndex + linesToDisplay {
                    m.scrollIndex++
                }
            }  
*/ 

        case "enter":
           	if m.activeButton == 0 {
       			m.currentOperatingInstructions = "\n\n\t Editor Mode: Press 'OK' to apply settings, 'Cancel' to leave"
				m.tree.SetEditable(true)
           	} else if m.activeButton == 1 {
				m.tree.SetEditable(false)
       			m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"
            	if selectedItem, ok := m.list.SelectedItem().(item); ok {
					if selectedItem.title == "Network SSID List" { 
						root := m.tree.Nodes()
                   		C.exec(C.CString("set_ssid OneWifiMesh"), C.strlen(C.CString("set_ssid OneWifiMesh")), treeToNodes(&root[0]))
					} else if selectedItem.title == "Radios" {

					} 
				}
           	} else if m.activeButton == 2 {
				m.tree.SetEditable(false)
       			m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"
			}

        case "c":
            netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.tree.Cursor()))
            if uint(C.can_collapse_node(netNode)) == 1 {

                tmp := m.displayedNetNode
                m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, m.displayedNetNode, C.uint(m.tree.Cursor()), true)
                defer C.free_network_tree(tmp);
                //str := C.get_network_tree_string(m.displayedNetNode)
                //spew.Fdump(m.dump, "Collapse", m.tree.Cursor())
                //C.dump_lib_dbg(str)

                treeNode := make([]etree.Node, 1)
                nodesToTree(m.displayedNetNode, &treeNode[0])
				m.tree.SetNodes(treeNode)
            }

        case "e":
            netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.tree.Cursor()))
            if (uint(C.can_expand_node(netNode))) == 1 {

                tmp := m.displayedNetNode
                m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, m.displayedNetNode, C.uint(m.tree.Cursor()), false)
                defer C.free_network_tree(tmp);

                //str := C.get_network_tree_string(m.displayedNetNode)
                //spew.Fdump(m.dump, "Expand", m.tree.Cursor())
                //C.dump_lib_dbg(str)

                treeNode := make([]etree.Node, 1)
                nodesToTree(m.displayedNetNode, &treeNode[0])
				m.tree.SetNodes(treeNode)
            }


        case "q":
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
	var cmd tea.Cmd

	m.tree, cmd = m.tree.Update(msg)
	cmds = append(cmds, cmd)

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
		
	content := m.tree.TreeView()
	m.scrollContent = splitIntoLines(content)

    var statusView string
    if len(m.scrollContent) > 0 {
        end := m.scrollIndex + linesToDisplay
        if end > len(m.scrollContent) {
            end = len(m.scrollContent)
        }

		styledContent := jsonStyle.Render(strings.Join(m.scrollContent[m.scrollIndex:end], "\n"))

        //statusView = styledContent + "\n\n\t Press 'w' to scroll up, 's' to scroll down"
        statusView = styledContent + m.currentOperatingInstructions
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

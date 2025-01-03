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
	"github.com/rdkcentral/unified-wifi-mesh/src/cli/etree"
	"unsafe"
	"fmt"
	"os"
	"time"
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
	
	NetworkTopologyCmd = 1
	NetworkSSIDListCmd = 2
	RadioListCmd = 3
	ChannelsListCmd = 4
	ClientDevicesCmd = 5
	NetworkPolicyCmd = 6
	NeighborsListCmd = 7
	SteerDevicesCmd = 8
	NetworkMetricsCmd = 9
	DeviceOnboardingCmd = 10

	GET = 0
	GETX = 1 
	SET = 2 

	BTN_UPDATE	= 0
	BTN_OK	= 1
	BTN_CANCEL	= 2
	BTN_MAX = 3
)

var (
    appStyle = lipgloss.NewStyle().Padding(1, 2)

    titleStyle = lipgloss.NewStyle().
    		Foreground(lipgloss.Color("#606060")).
    		Bold(true)

    menuBodyStyle = lipgloss.NewStyle().
    		Background(lipgloss.Color("#ffffff"))

    viewBodyStyle = lipgloss.NewStyle().
    		Background(lipgloss.Color("#ebebeb"))

    jsonStyle = lipgloss.NewStyle().
    		Border(lipgloss.RoundedBorder()).
    		Background(lipgloss.Color("#ffffff")).
    		Foreground(lipgloss.Color("#ffffff"))

    listItemStyle = lipgloss.NewStyle().
    		Foreground(lipgloss.Color("#aaaaaa"))

	activeItemStyle = listItemStyle.Copy().
    		Foreground(lipgloss.Color("#606060")).
    		Align(lipgloss.Center).
    		Bold(true)

    buttonStyle = lipgloss.NewStyle().
    		Foreground(lipgloss.Color("#ffffff")).
    		Background(lipgloss.Color("#bfbfbf")).
    		Padding(0, 1).
    		MarginRight(3).
    		Width(25).
    		Align(lipgloss.Center).
    		MarginBackground(lipgloss.Color("#ebebeb"))

    activeButtonStyle = buttonStyle.Copy().
    		Background(lipgloss.Color("#606060")).
    		Bold(true)

	styleDoc = lipgloss.NewStyle().Padding(1)
)

type item struct {
    title    string
    isActive bool
}

func (i item) Title() string {
    if i.isActive {
        return activeItemStyle.Render(i.title)
    }
    return listItemStyle.Render(i.title)
}

func (i item) Description() string { return "" }
func (i item) FilterValue() string { return i.title }

type EasyMeshCmd struct {
	Title		string
	GetCommand		string
	GetCommandEx		string
	SetCommand		string
	Help		string
}

var emCommands = map[int]EasyMeshCmd {
    NetworkTopologyCmd: 		{"Network Topology", "get_bss OneWifiMesh", "", "", ""},
    NetworkPolicyCmd: 		{"Network Policy", "get_policy OneWifiMesh", "get_policy OneWifiMesh", "set_policy OneWifiMesh", ""},
    NetworkSSIDListCmd: 	{"SSID List", "get_ssid OneWifiMesh", "get_ssid OneWifiMesh", "set_ssid OneWifiMesh", ""},
    RadioListCmd: 			{"WiFi Radios", "get_radio OneWifiMesh", "", "", ""},
    ChannelsListCmd: 		{"WiFi Channels", "get_channel OneWifiMesh", "get_channel OneWifiMesh 1", "set_channel OneWifiMesh", ""},
    NeighborsListCmd: 		{"WiFi Neighbors", "get_channel OneWifiMesh", "get_channel OneWifiMesh 2", "scan_channel OneWifiMesh", ""},
    ClientDevicesCmd: 		{"Client Connections", "get_sta OneWifiMesh", "", "", ""},
    SteerDevicesCmd: 		{"Optimize Connections", "get_sta OneWifiMesh", "get_sta OneWifiMesh 1", "steer_sta OneWifiMesh", ""},
    NetworkMetricsCmd: 		{"Network Metrics", "", "", "", ""},
    DeviceOnboardingCmd: 		{"Onboarding & Provisioning", "", "", "", ""},
	
}

type model struct {
    list          list.Model
    statusMessage string
	currentOperatingInstructions	string
    scrollContent []string
    scrollIndex   int
    activeButton  int
	viewWidth		int
	viewHeight		int
	menuWidth		int
	menuHeight		int
	menuInstructionsHeight	int
	bottomSpace	int
	rightSpace	int
    tree   etree.Model
    currentNetNode   *C.em_network_node_t
    displayedNetNode   *C.em_network_node_t
    cursor int
	quit	chan bool
	ticker	*time.Ticker
	timer	*time.Timer
    dump 	*os.File
}

func newModel() model {

	var items []list.Item

	for _, value := range emCommands {
		items  = append(items, item{title: value.Title})
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
        h = 50
    }
    top, right, bottom, left := styleDoc.GetPadding()
    w = w - left - right
    h = h - top - bottom

	nodes := make([]etree.Node, 1)

    nodes[0].Key = "OneWifiMesh"
    nodes[0].Type = etree.NodeTypeObject
    nodes[0].Children = nil

    dump, _ := os.OpenFile("messages.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
    C.init_lib_dbg(C.CString("messages_lib.log"))

    return model{
		menuWidth: 35,
		menuInstructionsHeight: 3,
		bottomSpace: 10,
		rightSpace: 3,
        list:          commandList,
        statusMessage: "",
		activeButton: BTN_CANCEL,
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

	m.timer = time.NewTimer(1 * time.Second)
	m.ticker = time.NewTicker(5 * time.Second)
	m.quit = make(chan bool)

	m.list.Select(0)
	go m.timerHandler()

    return textinput.Blink
}

func (m *model) timerHandler() {
	for {
		select {
			case <- m.timer.C:
				if listItem, ok := m.list.Items()[0].(item); ok {
					spew.Fdump(m.dump, listItem.title)
					m.execSelectedCommand(listItem.title, GET)
   				}


			case <- m.ticker.C:
				spew.Fdump(m.dump, "5 second ticker fired")

			case <- m.quit:
				m.ticker.Stop()
				return
		}	
	}
}

func (m model) treeToNodes(treeNode *etree.Node) *C.em_network_node_t {
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
			netNode.child[i] = m.treeToNodes(&treeNode.Children[i])
		}

		netNode.num_children = C.uint(len(treeNode.Children))
	}

	return netNode
}

func (m model) nodesToTree(netNode *C.em_network_node_t, treeNode *etree.Node) {
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
                    m.nodesToTree(childNetNode, &treeNode.Children[i])
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
            m.nodesToTree(childNetNode, &treeNode.Children[i])
        }
    }
}

func (m *model) execSelectedCommand(cmdStr string, cmdType int) {
	for _, value := range emCommands {
		if cmdStr == value.Title {
			switch cmdType {
				case GET:
					m.currentNetNode = C.exec(C.CString(value.GetCommand), C.strlen(C.CString(value.GetCommand)), nil)	
        			spew.Fdump(m.dump, value.GetCommand)
					treeNode := make([]etree.Node, 1)
                    m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
                    m.nodesToTree(m.displayedNetNode, &treeNode[0])
                    m.tree.SetNodes(treeNode)

				case GETX:
					if value.GetCommandEx != "" {
						m.currentNetNode = C.exec(C.CString(value.GetCommandEx), C.strlen(C.CString(value.GetCommandEx)), nil)	
        				spew.Fdump(m.dump, value.GetCommandEx)
						treeNode := make([]etree.Node, 1)
                    	m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
                    	m.nodesToTree(m.displayedNetNode, &treeNode[0])
                    	m.tree.SetNodes(treeNode)
					}

				case SET:
					if value.SetCommand != "" {
						root := m.tree.Nodes()
                   		C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), m.treeToNodes(&root[0]))
					}
			}
		}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        w, h:= appStyle.GetFrameSize()
		spew.Fprintf(m.dump, "Frame Width: %d Frame Height: %d Msg Width: %d Msg Height: %d\n", 
								w, h, msg.Width, msg.Height)

		m.menuHeight = msg.Height - m.bottomSpace - m.menuInstructionsHeight
		m.viewWidth = msg.Width - m.menuWidth - m.rightSpace
		m.viewHeight = msg.Height - m.bottomSpace

    case tea.KeyMsg:
        switch msg.String() {
        case "tab":
            m.activeButton = (m.activeButton + 1) % BTN_MAX

		case "j", "k":
			m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"

			if m.activeButton != BTN_UPDATE {
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
					m.execSelectedCommand(selectedItem.title, GET)
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
           	if m.activeButton == BTN_UPDATE {
       			m.currentOperatingInstructions = "\n\n\t Editor Mode: Press 'OK' to apply settings, 'Cancel' to leave"
            	if selectedItem, ok := m.list.SelectedItem().(item); ok {
					m.execSelectedCommand(selectedItem.title, GETX)
				}
				m.tree.SetEditable(true)
           	} else if m.activeButton == BTN_OK {
				m.tree.SetEditable(false)
       			m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"
            	if selectedItem, ok := m.list.SelectedItem().(item); ok {
					m.execSelectedCommand(selectedItem.title, SET)
				}
           	} else if m.activeButton == BTN_CANCEL {
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
                m.nodesToTree(m.displayedNetNode, &treeNode[0])
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
                m.nodesToTree(m.displayedNetNode, &treeNode[0])
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
    m.list.SetSize(m.menuWidth, m.menuHeight)
    menuView := m.list.View()

    instructions := lipgloss.NewStyle().
    		Foreground(lipgloss.Color("#606060")).
    		Background(lipgloss.Color("#FFFFFF")).
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

		styledContent := jsonStyle.Width(m.viewWidth - 10).Render(strings.Join(m.scrollContent[m.scrollIndex:end], "\n"))

        //statusView = styledContent + "\n\n\t Press 'w' to scroll up, 's' to scroll down"
        statusView = styledContent + m.currentOperatingInstructions
    } else {
        statusView = m.statusMessage
    }
    
    updateButton := buttonStyle.Render("Update")
    okButton := buttonStyle.Render("OK")
    cancelButton := buttonStyle.Render("Cancel")
    
	switch m.activeButton {
        case BTN_UPDATE:
            updateButton = activeButtonStyle.Render("Update")

        case BTN_OK:
            okButton = activeButtonStyle.Render("OK")

        case BTN_CANCEL:
            cancelButton = activeButtonStyle.Render("Cancel")
    }

    buttons := lipgloss.JoinHorizontal(lipgloss.Center, updateButton, okButton, cancelButton)
    centeredButtons := lipgloss.NewStyle().Width(100).Align(lipgloss.Center).Render(buttons)
    statusView = statusView + "\n\n" + centeredButtons

    combinedView := lipgloss.JoinHorizontal(
        lipgloss.Top,
        menuBodyStyle.Width(m.menuWidth).Height(m.menuHeight).Render(menuViewWithInstructions),
        viewBodyStyle.Width(m.viewWidth).Height(m.viewHeight).Render(statusView),
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

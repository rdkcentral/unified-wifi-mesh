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
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/davecgh/go-spew/spew"
	"github.com/rdkcentral/unified-wifi-mesh/src/cli/etree"
	"golang.org/x/term"
)

const (
	linesToDisplay int = 38
	
	NetworkTopologyCmd = "Network Topology"
	NetworkSSIDListCmd = "SSID List"
	RadioListCmd = "WiFi Radios"
	ChannelsListCmd = "WiFi Channels"
	ClientDevicesCmd = "Client Connections"
	NetworkPolicyCmd = "Network Policy"
	NeighborsListCmd = "WiFi Neighbors"
	SteerDevicesCmd = "Optimize Client Connections"
	NetworkMetricsCmd = "Network Metrics"
	DeviceOnboardingCmd = "Onboarding & Provisioning"
	WiFiEventsCmd = "WiFi Events"
	WiFiResetCmd = "WiFi Reset"
	DebugCmd = "Debugging & Testing"

	GET = 0
	GETX = 1 
	SET = 2 

	BTN_UPDATE	= 0
	BTN_APPLY	= 1
	BTN_CANCEL	= 2
	BTN_MAX = 3
)

var p *tea.Program

var (
    appStyle = lipgloss.NewStyle().Padding(1, 2)

    titleStyle = lipgloss.NewStyle().
    		Foreground(lipgloss.Color("#606060")).
    		Bold(true)

    menuBodyStyle = lipgloss.NewStyle().
    		Background(lipgloss.Color("#ffffff"))

    canvasStyle = lipgloss.NewStyle().
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
	LoadOrder	int
	GetCommand		string
	GetCommandEx		string
	SetCommand		string
	Help		string
}

type model struct {
	platform	string
    list          list.Model
    statusMessage string
	currentOperatingInstructions	string
    scrollContent []string
    scrollIndex   int
    activeButton  int
	viewWidth		int
	viewHeight		int
	canvasWidth		int
	canvasHeight		int
	menuWidth		int
	menuHeight		int
	menuInstructionsHeight	int
	bottomSpace	int
	rightSpace	int
    tree   etree.Model
    currentNetNode   *C.em_network_node_t
    displayedNetNode   *C.em_network_node_t
	quit	chan bool
	ticker	*time.Ticker
	timer	*time.Timer
	easyMeshCommands	map[string]EasyMeshCmd
	contentUpdated		bool
    dump 	*os.File
}

type refreshUIMsg struct {
    index    int
}

func newModel(platform string) model {

	easyMeshCommands := map[string]EasyMeshCmd {
    	NetworkTopologyCmd:         {NetworkTopologyCmd, 0, "get_bss OneWifiMesh", "", "", ""},
        NetworkPolicyCmd:       {NetworkPolicyCmd, 1, "get_policy OneWifiMesh", "get_policy OneWifiMesh", "set_policy OneWifiMesh", ""},
        NetworkSSIDListCmd:     {NetworkSSIDListCmd, 2, "get_ssid OneWifiMesh", "get_ssid OneWifiMesh", "set_ssid OneWifiMesh", ""},
        RadioListCmd:           {RadioListCmd, 3, "get_radio OneWifiMesh", "", "", ""},
        ChannelsListCmd:        {ChannelsListCmd, 4, "get_channel OneWifiMesh", "get_channel OneWifiMesh 1", "set_channel OneWifiMesh", ""},
        NeighborsListCmd:       {NeighborsListCmd, 5, "get_channel OneWifiMesh", "get_channel OneWifiMesh 2", "scan_channel OneWifiMesh", ""},
        ClientDevicesCmd:       {ClientDevicesCmd, 6, "get_sta OneWifiMesh", "", "", ""},
        SteerDevicesCmd:        {SteerDevicesCmd, 7, "get_sta OneWifiMesh", "get_sta OneWifiMesh 1", "steer_sta OneWifiMesh", ""},
        NetworkMetricsCmd:      {NetworkMetricsCmd, 8, "", "", "", ""},
        DeviceOnboardingCmd:        {DeviceOnboardingCmd, 9, "", "", "", ""},
        WiFiEventsCmd:      {WiFiEventsCmd, 10, "", "", "", ""},
        WiFiResetCmd:       {WiFiResetCmd, 11, "get_network OneWifiMesh", "", "reset OneWifiMesh", ""},
        DebugCmd:       {DebugCmd, 12, "dev_test OneWifiMesh", "", "", ""},
    }
	
	var items []list.Item
	
	for i := 0; i < len(easyMeshCommands); i++ {
		for _, value := range easyMeshCommands { 
			if i == value.LoadOrder {
				items = append(items, item{title: value.Title})
				break
			}
		}
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

    return model {
		platform: platform,
		menuWidth: 35,
		menuInstructionsHeight: 3,
		bottomSpace: 10,
		rightSpace: 3,
        list:          commandList,
        statusMessage: "",
		activeButton: BTN_CANCEL,
		tree: etree.New(nodes, false, w, h, dump),
        dump: dump,
		easyMeshCommands: easyMeshCommands, 
		contentUpdated: false,
    }
}



func (m model) Init() tea.Cmd {
	var params *C.em_cli_params_t
	params = (*C.em_cli_params_t)(C.malloc(C.sizeof_em_cli_params_t))
	params.user_data = unsafe.Pointer(&m)
	params.cb_func = nil
	params.cli_type = C.em_cli_type_go
	C.init(params)
		
	m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"

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
                if listItem, ok := m.list.Items()[6].(item); ok {
                    m.execSelectedCommand(listItem.title, GET)
                    if p != nil {
                        p.Send(refreshUIMsg{index: 6})
                    }
                }

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
        } else {
			treeNode.Type = int(C.em_network_node_data_type_array_obj)
			treeNode.Value.Placeholder = "[]"
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
	for _, value := range m.easyMeshCommands {
		if cmdStr == value.Title {
			switch cmdType {
				case GET:
					if value.Title == DeviceOnboardingCmd {
						nodes, err := readJSONFile("DPPURI.json")
						if err != nil {
							spew.Fprintf(m.dump, "Error reading JSON file: %v\n", err)
							return
						}
						m.tree.SetNodes(nodes)
						return
					}
					if value.GetCommand == "" {
						m.tree.SetNodes([]etree.Node{})
						return
					}
					m.currentNetNode = C.exec(C.CString(value.GetCommand), C.strlen(C.CString(value.GetCommand)), nil)	
					if m.currentNetNode == nil {
						return
					}
					treeNode := make([]etree.Node, 1)
                    m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
                    m.nodesToTree(m.displayedNetNode, &treeNode[0])
                    m.tree.SetNodes(treeNode)
                	//str := C.get_network_tree_string(m.displayedNetNode)
					//C.dump_lib_dbg(str)

				case GETX:
					if value.GetCommandEx != "" {
						m.currentNetNode = C.exec(C.CString(value.GetCommandEx), C.strlen(C.CString(value.GetCommandEx)), nil)	
        				//spew.Fdump(m.dump, value.GetCommandEx)
						treeNode := make([]etree.Node, 1)
                    	m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
                    	m.nodesToTree(m.displayedNetNode, &treeNode[0])
                    	m.tree.SetNodes(treeNode)
					} else {
						switch value.Title {
							case WiFiResetCmd:
								m.currentNetNode = C.get_reset_tree(C.CString(m.platform))
								treeNode := make([]etree.Node, 1)
                    			m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, nil, 0xffff, false)
                    			m.nodesToTree(m.displayedNetNode, &treeNode[0])
                    			m.tree.SetNodes(treeNode)

							default:
						}	
					}

				case SET:
					if value.SetCommand == "" {
						return
					}
					if value.Title == DeviceOnboardingCmd {
						// Write current nodes to a JSON file (could be modified or unmodified)
						if err := writeJSONFile(m.tree.Nodes(), "DPPURI_sendable.json"); err != nil {
							spew.Fprintf(m.dump, "Error writing JSON: %v\n", err)
							return
						}
						spew.Fdump(m.dump, "Sending DPPURI JSON file")	
						// Network nodes not needed for DPPURI
						C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), nil)
						return
					}
    
					root := m.tree.Nodes()
               		C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), m.treeToNodes(&root[0]))
			}
		}
	}

	m.scrollIndex = 0
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd
	var cmd tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
		m.menuHeight = msg.Height - m.bottomSpace - m.menuInstructionsHeight
		m.canvasWidth = msg.Width - m.menuWidth - m.rightSpace
		m.canvasHeight = msg.Height - m.bottomSpace

    case tea.KeyMsg:
        switch msg.String() {
        case "tab":
			if m.contentUpdated == true {
            	m.activeButton = (m.activeButton + 1) % BTN_MAX
			} else {
				if m.activeButton == BTN_UPDATE {
					m.activeButton = BTN_CANCEL
				} else {
					m.activeButton = BTN_UPDATE
				}
			}

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
		
				m.contentUpdated = false
					
			}
        
		case "down":
			if m.scrollIndex < m.tree.Cursor() {
				m.scrollIndex++
			}
        
        case "up":
			if m.scrollIndex > 0 {
				m.scrollIndex--
			}
            	
        case "enter":
           	if m.activeButton == BTN_UPDATE {
       			m.currentOperatingInstructions = "\n\n\t Editor Mode: Press 'Apply' to apply settings, 'Cancel' to leave"
            	if selectedItem, ok := m.list.SelectedItem().(item); ok {
					m.contentUpdated = true
					m.execSelectedCommand(selectedItem.title, GETX)
				}
				m.tree.SetEditable(true)
           	} else if m.activeButton == BTN_APPLY {
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

    case refreshUIMsg:
        //spew.Fdump(m.dump, "Refresh Data!", msg.index)
        newListModel, cmd := m.list.Update(msg)
        m.list = newListModel
        // Check if the current item is at index 6
        if listItem, ok := m.list.Items()[msg.index].(item); ok {
            listItem.isActive = msg.index == m.list.Index()
            m.list.SetItem(msg.index, listItem)
        }
        cmds = append(cmds, cmd)

        if selectedItem, ok := m.list.SelectedItem().(item); ok {
            if m.list.Index() == msg.index {
                m.execSelectedCommand(selectedItem.title, GET)
            }
        }
    }

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
	
	m.viewWidth = m.canvasWidth - 10

	if m.canvasHeight > 10 {
		m.viewHeight = m.canvasHeight - 10
	} else {
		m.viewHeight = m.canvasHeight
	}

    m.tree.SetSize(m.viewWidth, m.viewHeight)
	
	m.scrollContent = splitIntoLines(m.tree.TreeView())

    var statusView string

	start := 0

	if m.scrollIndex > m.viewHeight {
		start = m.scrollIndex - m.viewHeight
	}

	end := len(m.scrollContent) - 1
	if end > start + m.viewHeight {
		end = start + m.viewHeight
	}

	//spew.Fprintf(m.dump, "start: %d end: %d\n", start, end)
	 
	styledContent := jsonStyle.Width(m.viewWidth).Height(m.viewHeight).Render(strings.Join(m.scrollContent[start:end], "\n"))
	statusView = styledContent + m.currentOperatingInstructions
    
    updateButton := buttonStyle.Render("Update")
    applyButton := buttonStyle.Render("Apply")
    cancelButton := buttonStyle.Render("Cancel")
    
	switch m.activeButton {
        case BTN_UPDATE:
            updateButton = activeButtonStyle.Render("Update")

        case BTN_APPLY:
            applyButton = activeButtonStyle.Render("Apply")

        case BTN_CANCEL:
            cancelButton = activeButtonStyle.Render("Cancel")
    }

    buttons := lipgloss.JoinHorizontal(lipgloss.Center, updateButton, applyButton, cancelButton)
    centeredButtons := lipgloss.NewStyle().Width(100).Align(lipgloss.Center).Render(buttons)
    statusView = statusView + "\n\n" + centeredButtons

    combinedView := lipgloss.JoinHorizontal(
        lipgloss.Top,
        menuBodyStyle.Width(m.menuWidth).Height(m.menuHeight).Render(menuViewWithInstructions),
        canvasStyle.Width(m.canvasWidth).Height(m.canvasHeight).Render(statusView),
    )

    commonBorderStyle := lipgloss.NewStyle().
    	Border(lipgloss.RoundedBorder()).
    	BorderForeground(lipgloss.Color("#080563")).
    	Padding(0).
    	Bold(true)

    return commonBorderStyle.Render(combinedView)
}

func main() {
	if len(os.Args[1:]) != 1 {
        fmt.Println("Invalid Arguments, please specify platform name")
        os.Exit(1)
	}

    p = tea.NewProgram(newModel(os.Args[1]), tea.WithAltScreen())

    if _, err := p.Run(); err != nil {
        fmt.Println("Error running program:", err)
        os.Exit(1)
    }
}

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
	"regexp"
	"strconv"
	"strings"
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

	NetworkTopologyCmd    = "Network Topology"
	NetworkSSIDListCmd    = "SSID List"
	RadioListCmd          = "WiFi Radios"
	ChannelsListCmd       = "WiFi Channels"
	MLDReconfigurationCmd = "Multi Link Operations"
	ClientDevicesCmd      = "Client Connections"
	NetworkPolicyCmd      = "Network Policy"
	NeighborsListCmd      = "WiFi Neighbors"
	SteerDevicesCmd       = "Optimize Client Connections"
	BackhaulOptimizeCmd   = "Optimize Backhaul Connections"
	NetworkMetricsCmd     = "Network Metrics"
	DeviceOnboardingCmd   = "Onboarding & Provisioning"
	WiFiEventsCmd         = "WiFi Events"
	WiFiResetCmd          = "WiFi Reset"
	DebugCmd              = "Debugging & Testing"

	GET  = 0
	GETX = 1
	SET  = 2

	BTN_UPDATE = 0
	BTN_APPLY  = 1
	BTN_CANCEL = 2
	BTN_MAX    = 3
)

var program *tea.Program

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
	Title                string
	LoadOrder            int
	GetCommand           string
	GetCommandEx         string
	SetCommand           string
	Help                 string
	AllowUnmodifiedApply bool
}

func CreateEasyMeshCommands() map[string]EasyMeshCmd {
	return map[string]EasyMeshCmd{
		NetworkTopologyCmd: {
			Title:                NetworkTopologyCmd,
			LoadOrder:            0,
			GetCommand:           "get_bss OneWifiMesh",
			GetCommandEx:         "",
			SetCommand:           "",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		NetworkPolicyCmd: {
			Title:                NetworkPolicyCmd,
			LoadOrder:            1,
			GetCommand:           "get_policy OneWifiMesh",
			GetCommandEx:         "get_policy OneWifiMesh",
			SetCommand:           "set_policy OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		NetworkSSIDListCmd: {
			Title:                NetworkSSIDListCmd,
			LoadOrder:            2,
			GetCommand:           "get_ssid OneWifiMesh",
			GetCommandEx:         "get_ssid OneWifiMesh",
			SetCommand:           "set_ssid OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		RadioListCmd: {
			Title:                RadioListCmd,
			LoadOrder:            3,
			GetCommand:           "get_radio OneWifiMesh",
			GetCommandEx:         "",
			SetCommand:           "",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		ChannelsListCmd: {
			Title:                ChannelsListCmd,
			LoadOrder:            4,
			GetCommand:           "get_channel OneWifiMesh",
			GetCommandEx:         "get_channel OneWifiMesh 1",
			SetCommand:           "set_channel OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		MLDReconfigurationCmd: {
			Title:                MLDReconfigurationCmd,
			LoadOrder:            5,
			GetCommand:           "get_mld_config OneWifiMesh",
			GetCommandEx:         "",
			SetCommand:           "mld_reconfig OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		NeighborsListCmd: {
			Title:                NeighborsListCmd,
			LoadOrder:            6,
			GetCommand:           "scan_result OneWifiMesh",
			GetCommandEx:         "get_channel OneWifiMesh 2",
			SetCommand:           "scan_channel OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		ClientDevicesCmd: {
			Title:                ClientDevicesCmd,
			LoadOrder:            7,
			GetCommand:           "get_sta OneWifiMesh",
			GetCommandEx:         "",
			SetCommand:           "",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		SteerDevicesCmd: {
			Title:                SteerDevicesCmd,
			LoadOrder:            8,
			GetCommand:           "get_sta OneWifiMesh",
			GetCommandEx:         "get_sta OneWifiMesh 1",
			SetCommand:           "steer_sta OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		BackhaulOptimizeCmd: {
			Title:                BackhaulOptimizeCmd,
			LoadOrder:            9,
			GetCommand:           "get_sta OneWifiMesh",
			GetCommandEx:         "get_sta OneWifiMesh 1",
			SetCommand:           "steer_sta OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		NetworkMetricsCmd: {
			Title:                NetworkMetricsCmd,
			LoadOrder:            10,
			GetCommand:           "",
			GetCommandEx:         "",
			SetCommand:           "",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		DeviceOnboardingCmd: {
			Title:                DeviceOnboardingCmd,
			LoadOrder:            11,
			GetCommand:           "",
			GetCommandEx:         "",
			SetCommand:           "start_dpp",
			Help:                 "",
			AllowUnmodifiedApply: true,
		},
		WiFiEventsCmd: {
			Title:                WiFiEventsCmd,
			LoadOrder:            12,
			GetCommand:           "",
			GetCommandEx:         "",
			SetCommand:           "",
			Help:                 "",
			AllowUnmodifiedApply: false,
		},
		WiFiResetCmd: {
			Title:                WiFiResetCmd,
			LoadOrder:            13,
			GetCommand:           "get_network OneWifiMesh",
			GetCommandEx:         "",
			SetCommand:           "reset OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: true,
		},
		DebugCmd: {
			Title:                DebugCmd,
			LoadOrder:            14,
			GetCommand:           "dev_test OneWifiMesh 0",
			GetCommandEx:         "dev_test OneWifiMesh 1",
			SetCommand:           "set_dev_test OneWifiMesh",
			Help:                 "",
			AllowUnmodifiedApply: true,
		},
	}
}

type MeshViews struct {
	platform                     string
	list                         list.Model
	statusMessage                string
	currentOperatingInstructions string
	scrollContent                []string
	scrollIndex                  int
	activeButton                 int
	viewWidth                    int
	viewHeight                   int
	canvasWidth                  int
	canvasHeight                 int
	menuWidth                    int
	menuHeight                   int
	menuInstructionsHeight       int
	bottomSpace                  int
	rightSpace                   int
	tree                         etree.Model
	currentNetNode               *C.em_network_node_t
	displayedNetNode             *C.em_network_node_t
	easyMeshCommands             map[string]EasyMeshCmd
	updateButtonClicked          bool
	dump                         *os.File
}

type refreshUIMsg struct {
	index int
}

type DebugTest struct {
	num_iteration                [5]int
	test_type                    [5]int
	enabled                      [5]int
	num_of_iteration_completed   [5]int
	current_iteration_inprogress [5]int
	test_status                  [5]string
	configure_em                 [5]int
	haul_type                    string
	freq_band                    int
	num_of_test                  int
	index                        int
	num_of_em_test_enabled       int
	num_online_em                int
	num_failed_em                int
}

var debug_test DebugTest
var test_init = 0

func newMeshViews(platform string, dump *os.File) *MeshViews {

	easyMeshCommands := CreateEasyMeshCommands()
	size := len(easyMeshCommands)

	items := make([]list.Item, size)

	for _, value := range easyMeshCommands {
		if value.LoadOrder >= size {
			continue
		}
		items[value.LoadOrder] = item{title: value.Title}
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

	return &MeshViews{
		platform:               platform,
		scrollIndex:            0,
		menuWidth:              35,
		menuInstructionsHeight: 3,
		bottomSpace:            10,
		rightSpace:             3,
		list:                   commandList,
		statusMessage:          "",
		activeButton:           BTN_CANCEL,
		tree:                   etree.New(nodes, false, w, h, dump),
		dump:                   dump,
		easyMeshCommands:       easyMeshCommands,
		updateButtonClicked:    false,
	}
}

func (m MeshViews) Init() tea.Cmd {
	spew.Fprintf(m.dump, "Mesh Views Init\n")
	m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"

	m.list.Select(0)

	return textinput.Blink
}

func (m MeshViews) nodestraverse_to_getdevconfig(netNode *C.em_network_node_t) {
	var str *C.char
	nodeType := C.get_node_type(netNode)
	if nodeType == C.em_network_node_data_type_array_obj {
		if int(netNode.num_children) > 0 {
			childNetNode := C.get_child_node_at_index(netNode, 0)
			childNodeType := C.get_node_type(childNetNode)
			if (childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
				(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true) {
				var arrNodeType C.em_network_node_data_type_t
				str = C.get_node_array_value(netNode, &arrNodeType)
				if C.GoString(&netNode.key[0]) == "em" {
					temp := C.GoString(str)
					var em_temp = strings.Split(temp, ",")
					if em_temp[2] == " Test_Enabled:1" {
						debug_test.num_of_em_test_enabled = debug_test.num_of_em_test_enabled + 1
					}
					if em_temp[3] == " Online] " {
						debug_test.num_online_em = debug_test.num_online_em + 1
					}
					if em_temp[3] == " Config-failed] " {
						debug_test.num_failed_em = debug_test.num_failed_em + 1
					}
				}
				C.free_node_value(str)
			} else {
				if C.GoString(&netNode.key[0]) == "dev_test" {
					debug_test.num_of_test = int(netNode.num_children)
					for i := 0; i < int(netNode.num_children); i++ {
						childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
						m.nodestraverse_to_getdevconfig(childNetNode)
					}
				}
			}
		}

	} else if (nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
		(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true) {
		str = C.get_node_scalar_value(netNode)
		if C.GoString(&netNode.key[0]) == "Test_type" {
			if C.GoString(str) == "ssid_change" {
				debug_test.index = 0
			} else if C.GoString(str) == "channel_change" {
				debug_test.index = 1
			}
		}
		if C.GoString(&netNode.key[0]) == "No_of_iteration" {
			debug_test.num_iteration[debug_test.index] = int(netNode.value_int)
		}
		if C.GoString(&netNode.key[0]) == "Test_enabled" {
			debug_test.enabled[debug_test.index] = int(netNode.value_int)
		}
		if C.GoString(&netNode.key[0]) == "Num_of_iteration_completed" {
			debug_test.num_of_iteration_completed[debug_test.index] = int(netNode.value_int)
		}
		if C.GoString(&netNode.key[0]) == "Current_iteration_inprogress" {
			debug_test.current_iteration_inprogress[debug_test.index] = int(netNode.value_int)
		}
		if C.GoString(&netNode.key[0]) == "Test_status" {
			debug_test.test_status[debug_test.index] = C.GoString(&netNode.value_str[0])
		}
		if C.GoString(&netNode.key[0]) == "Configure_active_em" {
			debug_test.configure_em[debug_test.index] = int(netNode.value_int)
		}
		if C.GoString(&netNode.key[0]) == "HaulType" {
			debug_test.haul_type = C.GoString(&netNode.value_str[0])
			//C.dump_lib_dbg(&netNode.value_str[0])
		}
		//C.dump_lib_dbg(str)
		C.free_node_value(str)
	} else {
		for i := 0; i < int(netNode.num_children); i++ {
			childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
			m.nodestraverse_to_getdevconfig(childNetNode)
		}
	}
}

func (m MeshViews) nodetraverse_to_enable_test(netNode *C.em_network_node_t) {
	var str *C.char
	nodeType := C.get_node_type(netNode)
	if nodeType == C.em_network_node_data_type_array_obj {
		if int(netNode.num_children) > 0 {
			childNetNode := C.get_child_node_at_index(netNode, 0)
			childNodeType := C.get_node_type(childNetNode)
			if (childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
				(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true) {
				var arrNodeType C.em_network_node_data_type_t
				str = C.get_node_array_value(netNode, &arrNodeType)
				C.free_node_value(str)
			} else {
				if C.GoString(&netNode.key[0]) == "dev_test" {
					debug_test.num_of_test = int(netNode.num_children)
					//fmt.Printf("debug_test\t %s - %d\n", C.GoString(&netNode.key[0]), debug_test.num_of_test )
					for i := 0; i < int(netNode.num_children); i++ {
						childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
						m.nodetraverse_to_enable_test(childNetNode)
					}
				}
			}
		}

	} else if (nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
		(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true) {
		str = C.get_node_scalar_value(netNode)
		if C.GoString(&netNode.key[0]) == "Configure_active_em" {
			netNode.value_int = 1
		}
		//C.dump_lib_dbg(str)
		C.free_node_value(str)
	} else {
		for i := 0; i < int(netNode.num_children); i++ {
			childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
			m.nodetraverse_to_enable_test(childNetNode)
		}
	}
}

func (m MeshViews) nodetraverse_to_update_dev_testconfigs(netNode *C.em_network_node_t) {
	var str *C.char
	nodeType := C.get_node_type(netNode)
	if nodeType == C.em_network_node_data_type_array_obj {
		if int(netNode.num_children) > 0 {
			childNetNode := C.get_child_node_at_index(netNode, 0)
			childNodeType := C.get_node_type(childNetNode)
			if (childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
				(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true) {
				var arrNodeType C.em_network_node_data_type_t
				str = C.get_node_array_value(netNode, &arrNodeType)
				//C.dump_lib_dbg(str)
				C.free_node_value(str)
			} else {
				if C.GoString(&netNode.key[0]) == "dev_test" {
					debug_test.num_of_test = int(netNode.num_children)
					for i := 0; i < int(netNode.num_children); i++ {
						childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
						m.nodetraverse_to_update_dev_testconfigs(childNetNode)
					}
				}
			}
		}

	} else if (nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
		(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true) {
		str = C.get_node_scalar_value(netNode)
		if C.GoString(&netNode.key[0]) == "Test_type" {
			if C.GoString(str) == "ssid_change" {
				debug_test.index = 0
			} else if C.GoString(str) == "channel_change" {
				debug_test.index = 1
			}
		}
		if C.GoString(&netNode.key[0]) == "No_of_iteration" {
			netNode.value_int = C.uint(debug_test.num_iteration[debug_test.index])
		}
		if C.GoString(&netNode.key[0]) == "Test_enabled" {
			netNode.value_int = C.uint(debug_test.enabled[debug_test.index])
		}
		if C.GoString(&netNode.key[0]) == "Num_of_iteration_completed" {
			netNode.value_int = C.uint(debug_test.num_of_iteration_completed[debug_test.index])
		}
		if C.GoString(&netNode.key[0]) == "Current_iteration_inprogress" {
			netNode.value_int = C.uint(debug_test.current_iteration_inprogress[debug_test.index])
		}
		if C.GoString(&netNode.key[0]) == "Test_status" {
			var len = len(debug_test.test_status[debug_test.index])
			C.strncpy(&netNode.value_str[0], C.CString(debug_test.test_status[debug_test.index]), C.ulong(len))
			netNode.value_str[len] = C.char('\000')
		}
		if C.GoString(&netNode.key[0]) == "Configure_active_em" {
			netNode.value_int = 0
		}
		//C.dump_lib_dbg(str)
		C.free_node_value(str)
	} else {
		for i := 0; i < int(netNode.num_children); i++ {
			childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
			m.nodetraverse_to_update_dev_testconfigs(childNetNode)
		}
	}

}

var parent *C.em_network_node_t

func (m MeshViews) nodetraverse_to_update_ssidconfigs(netNode *C.em_network_node_t) {
	var str *C.char
	nodeType := C.get_node_type(netNode)
	if C.GoString(&netNode.key[0]) == "SSID" {
		parent = netNode
	}
	if nodeType == C.em_network_node_data_type_array_obj {
		if int(netNode.num_children) > 0 {
			childNetNode := C.get_child_node_at_index(netNode, 0)
			childNodeType := C.get_node_type(childNetNode)
			if (childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
				(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true) {
				var arrNodeType C.em_network_node_data_type_t
				str = C.get_node_array_value(netNode, &arrNodeType)
				if C.GoString(&netNode.key[0]) == "HaulType" {
					haultype := strings.ReplaceAll(C.GoString(str), " ", "")
					if debug_test.haul_type == haultype {
						updateNetNode := parent
						reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
						haultype := reg.ReplaceAllString(haultype, "")
						temp := haultype + strconv.Itoa(debug_test.current_iteration_inprogress[0]+1) + string('\x00')
						var len = len(temp)
						C.strncpy(&updateNetNode.value_str[0], C.CString(temp), C.ulong(len))
						updateNetNode.value_str[len] = C.char('\000')
						//C.dump_lib_dbg(&updateNetNode.value_str[0]);
					}
				}
				//C.dump_lib_dbg(str)
				C.free_node_value(str)
			} else {
				for i := 0; i < int(netNode.num_children); i++ {
					childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
					if C.GoString(&childNetNode.key[0]) == "SSID" {
						parent = netNode
					}
					m.nodetraverse_to_update_ssidconfigs(childNetNode)
				}
			}
		}
	} else if (nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
		(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true) {
		str = C.get_node_scalar_value(netNode)
		C.free_node_value(str)
	} else {
		for i := 0; i < int(netNode.num_children); i++ {
			childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
			if C.GoString(&netNode.key[0]) == "SSID" {
				parent = childNetNode
			}
			m.nodetraverse_to_update_ssidconfigs(childNetNode)
		}
	}
}

func (m MeshViews) dev_test_handler() {
	var currentNetNode *C.em_network_node_t
	var displayedNetNode *C.em_network_node_t
	var updateNetNode *C.em_network_node_t
	var update_ssidNode *C.em_network_node_t

	value := m.getEMCommand(DebugCmd)
	currentNetNode = C.exec(C.CString(value.GetCommand), C.strlen(C.CString(value.GetCommand)), nil)
	displayedNetNode = C.clone_network_tree_for_display(currentNetNode, nil, 0xffff, false)
	debug_test.num_of_em_test_enabled = 0
	debug_test.num_online_em = 0
	debug_test.num_failed_em = 0
	m.nodestraverse_to_getdevconfig(displayedNetNode)
	//str := C.get_network_tree_string(displayedNetNode)
	//C.dump_lib_dbg(str)
	C.free_network_tree(currentNetNode)
	for i := 0; i < int(debug_test.num_of_test); i++ {
		//fmt.Printf("no of test=%d status=%d comp=%d inpr=%d sta=@%s@ failed=%d", debug_test.num_iteration[i], debug_test.enabled[i], debug_test.num_of_iteration_completed[i], debug_test.current_iteration_inprogress[i], debug_test.test_status[i], debug_test.num_failed_em)
		if (debug_test.enabled[i] == 1) && (test_init == 0) {
			if debug_test.test_status[i] != "In-Progress" {
				updateNetNode = C.exec(C.CString(value.GetCommandEx), C.strlen(C.CString(value.GetCommandEx)), nil)
				displayedNetNode = C.clone_network_tree_for_display(updateNetNode, nil, 0xffff, false)
				m.nodetraverse_to_enable_test(displayedNetNode)
				C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), displayedNetNode)
				return
			} else if debug_test.test_status[i] == "In-Progress" {
				if (debug_test.num_failed_em > 0) || (debug_test.num_of_em_test_enabled == 0) {

					//Test Failed - Disable the test enable, set Status to fail and set current iteration to zero /no em is in configured state
					debug_test.enabled[i] = 0
					debug_test.test_status[i] = "Failed"
					debug_test.current_iteration_inprogress[i] = 0
				} else if debug_test.num_of_iteration_completed[i] == debug_test.num_iteration[i] {

					//Test Complete
					debug_test.enabled[i] = 0
					debug_test.test_status[i] = "Complete"
				} else if (debug_test.num_online_em == debug_test.num_of_em_test_enabled) && (debug_test.num_online_em > 0) && (debug_test.current_iteration_inprogress[i] > 0) && (debug_test.enabled[i] == 1) {

					//EM configured for all the EM - Update current iteration complete
					debug_test.num_of_iteration_completed[i] = debug_test.num_of_iteration_completed[i] + 1
				}
				if (debug_test.current_iteration_inprogress[i] == debug_test.num_of_iteration_completed[i]) && (debug_test.enabled[i] == 1) && (debug_test.num_of_iteration_completed[i] != debug_test.num_iteration[i]) {

					// Test Complete - Start next iteration of set SSID
					value := m.getEMCommand(NetworkSSIDListCmd)
					updateNetNode = C.exec(C.CString(value.GetCommandEx), C.strlen(C.CString(value.GetCommandEx)), nil)
					update_ssidNode = C.clone_network_tree_for_display(updateNetNode, nil, 0xffff, false)
					m.nodetraverse_to_update_ssidconfigs(update_ssidNode)
					//str := C.get_network_tree_string(update_ssidNode)
					//C.dump_lib_dbg(str)
					//C.free(str)
					C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), update_ssidNode)
					debug_test.current_iteration_inprogress[i] = debug_test.current_iteration_inprogress[i] + 1
					test_init = 3
				}
				value := m.getEMCommand(DebugCmd)
				currentNetNode = C.exec(C.CString(value.GetCommand), C.strlen(C.CString(value.GetCommand)), nil)
				displayedNetNode = C.clone_network_tree_for_display(currentNetNode, nil, 0xffff, false)
				//fmt.Printf("no of test=%d status=%d comp=%d inpr=%d sta=%s", debug_test.num_iteration[i], debug_test.enabled[i], debug_test.num_of_iteration_completed[i], debug_test.current_iteration_inprogress[i], debug_test.test_status[i])
				//fmt.Printf("Onile=%d failed=%d", debug_test.num_online_em, debug_test.num_failed_em);
				m.nodetraverse_to_update_dev_testconfigs(displayedNetNode)
				C.exec(C.CString(value.SetCommand), C.strlen(C.CString(value.SetCommand)), displayedNetNode)
			}
			break
		}
	}
	if test_init > 0 {
		test_init--
	}
}

func (m MeshViews) treeToNodes(treeNode *etree.Node) *C.em_network_node_t {
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

func (m MeshViews) nodesToTree(netNode *C.em_network_node_t, treeNode *etree.Node) {
	var str *C.char

	//treeNode.Value = C.GoString(&netNode.key[0]) + "." + fmt.Sprintf("%d", uint(netNode.display_info.node_ctr)) + "." + fmt.Sprintf("%d", uint(netNode.display_info.orig_node_ctr))
	treeNode.Key = C.GoString(&netNode.key[0])
	nodeType := C.get_node_type(netNode)

	if nodeType == C.em_network_node_data_type_array_obj {
		if int(netNode.num_children) > 0 {
			childNetNode := C.get_child_node_at_index(netNode, 0)
			childNodeType := C.get_node_type(childNetNode)
			if (childNodeType == C.em_network_node_data_type_string) || (childNodeType == C.em_network_node_data_type_number) ||
				(childNodeType == C.em_network_node_data_type_false) || (childNodeType == C.em_network_node_data_type_true) {
				var arrNodeType C.em_network_node_data_type_t
				str = C.get_node_array_value(netNode, &arrNodeType)
				treeNode.Value = textinput.New()
				treeNode.Value.Placeholder = C.GoString(str)
				treeNode.Type = int(arrNodeType)
				C.free_node_value(str)
			} else {
				treeNode.Children = make([]etree.Node, uint(netNode.num_children))
				treeNode.Type = int(C.em_network_node_data_type_array_obj)
				if netNode.display_info.collapsed {
					treeNode.Collapsed = true
				}
				for i := 0; i < int(netNode.num_children); i++ {
					childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
					m.nodesToTree(childNetNode, &treeNode.Children[i])
				}
			}
		} else {
			treeNode.Type = int(C.em_network_node_data_type_array_obj)
			treeNode.Value.Placeholder = "[]"
		}

	} else if (nodeType == C.em_network_node_data_type_string) || (nodeType == C.em_network_node_data_type_number) ||
		(nodeType == C.em_network_node_data_type_false) || (nodeType == C.em_network_node_data_type_true) {
		str = C.get_node_scalar_value(netNode)
		treeNode.Type = int(nodeType)
		treeNode.Value = textinput.New()
		treeNode.Value.Placeholder = C.GoString(str)
		C.free_node_value(str)
	} else {
		treeNode.Children = make([]etree.Node, uint(netNode.num_children))
		treeNode.Type = int(nodeType)
		if netNode.display_info.collapsed {
			treeNode.Collapsed = true
		}
		for i := 0; i < int(netNode.num_children); i++ {
			childNetNode := C.get_child_node_at_index(netNode, C.uint(i))
			m.nodesToTree(childNetNode, &treeNode.Children[i])
		}
	}
}

func (m *MeshViews) getEMCommand(cmdStr string) *EasyMeshCmd {
	for _, value := range m.easyMeshCommands {
		if cmdStr == value.Title {
			return &value
		}
	}
	return nil
}

func (m *MeshViews) execSelectedCommand(cmdStr string, cmdType int) {

	value := m.getEMCommand(cmdStr)
	switch cmdType {
	case GET:
		if value.Title == DeviceOnboardingCmd {
			nodes, err := readDPPUriTxtFileToNodes("/tmp/DPPURI.txt")
			if err != nil {
				// fallback
				spew.Fprintf(m.dump, "Error reading /tmp/DPPURI.txt, trying current working directory: %v\n", err)
				nodes, err = readDPPUriTxtFileToNodes("DPPURI.txt")
				if err != nil {
					spew.Fprintf(m.dump, "Error reading fallback DPPURI.json: %v\n", err)
					return
				}
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

func (m MeshViews) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.menuHeight = msg.Height - m.bottomSpace - m.menuInstructionsHeight
		m.canvasWidth = msg.Width - m.menuWidth - m.rightSpace
		m.canvasHeight = msg.Height - m.bottomSpace

	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			curr_em_cmd := m.getEMCommand(m.list.SelectedItem().(item).title)
			if m.updateButtonClicked == true || curr_em_cmd.AllowUnmodifiedApply {
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

			if m.updateButtonClicked == false {
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
					m.updateButtonClicked = true
					m.execSelectedCommand(selectedItem.title, GETX)
				}
				m.tree.SetEditable(true)
			} else if m.activeButton == BTN_APPLY {
				m.tree.SetEditable(false)
				m.updateButtonClicked = false
				m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"
				if selectedItem, ok := m.list.SelectedItem().(item); ok {
					m.execSelectedCommand(selectedItem.title, SET)
				}
			} else if m.activeButton == BTN_CANCEL {
				m.tree.SetEditable(false)
				m.updateButtonClicked = false
				m.currentOperatingInstructions = "\n\n\t Press 'w' to scroll up, 's' to scroll down"
			}

		case "c":
			netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.tree.Cursor()))
			if netNode == nil {
				break
			}
			if uint(C.can_collapse_node(netNode)) == 1 {

				tmp := m.displayedNetNode
				m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, m.displayedNetNode, C.uint(m.tree.Cursor()), true)
				defer C.free_network_tree(tmp)
				//str := C.get_network_tree_string(m.displayedNetNode)
				//spew.Fdump(m.dump, "Collapse", m.tree.Cursor())
				//C.dump_lib_dbg(str)

				treeNode := make([]etree.Node, 1)
				m.nodesToTree(m.displayedNetNode, &treeNode[0])
				m.tree.SetNodes(treeNode)
			}

		case "e":
			netNode := C.get_node_from_node_ctr(m.displayedNetNode, C.uint(m.tree.Cursor()))
			if netNode == nil {
				break
			}
			if (uint(C.can_expand_node(netNode))) == 1 {

				tmp := m.displayedNetNode
				m.displayedNetNode = C.clone_network_tree_for_display(m.currentNetNode, m.displayedNetNode, C.uint(m.tree.Cursor()), false)
				defer C.free_network_tree(tmp)

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
		spew.Fdump(m.dump, "Refresh Data!", m.updateButtonClicked)
		if m.updateButtonClicked == false {
			newListModel, cmd := m.list.Update(msg)
			m.list = newListModel
			cmds = append(cmds, cmd)
			if selectedItem, ok := m.list.SelectedItem().(item); ok {
				m.execSelectedCommand(selectedItem.title, GET)
			}
		}

	case DebugTest:
		newListModel, cmd := m.list.Update(msg)
		m.list = newListModel
		cmds = append(cmds, cmd)
		if selectedItem, ok := m.list.SelectedItem().(item); ok {
			value := m.getEMCommand(selectedItem.title)
			if value.Title == DebugCmd {
				if m.activeButton != BTN_UPDATE {
					m.execSelectedCommand(selectedItem.title, GET)
				}
				m.dev_test_handler()
			}
		}
	}

	m.tree, cmd = m.tree.Update(message)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m MeshViews) View() string {
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
	if end > start+m.viewHeight {
		end = start + m.viewHeight
	}

	//spew.Fprintf(m.dump, "Scroll Index: %d View Height: %d start: %d end: %d\n", m.scrollIndex, m.viewHeight, start, end)

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

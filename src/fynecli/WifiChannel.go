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
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// classChannelMap struct to store channel capability
type classChannelMap struct {
	class       int
	channelList []int
}

// channelConfig struct to store previous configuration
type channelConfig struct {
	radioIndex int
	class      int
	channles   []int
}

// Global variable
var selectedChannelmap = map[int]map[int]map[int]bool{}

/* func: ShowWifiChannelChangeDialog()
 * Description:
 * Create a dialog box to configure wifi channel
 * Returns: NA
 */
func ShowWifiChannelChangeDialog(m *MeshViewsMgr) {
	prevSelectedBand := -1
	m.isEditing = true

	// Fetch tree for channel capability
	get_channel_cmd := C.CString("get_channel OneWifiMesh 3")
	defer C.free(unsafe.Pointer(get_channel_cmd))
	wifiChannelTree := C.exec(get_channel_cmd, C.strlen(get_channel_cmd), nil)

	//Get the DeviceList node
	deviceListTree := C.get_network_tree_by_key(wifiChannelTree, C.CString("DeviceList"))
	capabilityMap := getChannelCapabilityFromTree(deviceListTree)

	// Fetch tree for previous configuration tree
	get_channel_Pref_cmd := C.CString("get_channel OneWifiMesh 1")
	defer C.free(unsafe.Pointer(get_channel_Pref_cmd))
	wifiChannelUpdateTree := C.exec(get_channel_Pref_cmd, C.strlen(get_channel_Pref_cmd), nil)
	prevConfigMap := getConfiguredChannels(wifiChannelUpdateTree)

	// band and label mapping
	var bandOptions []string
	bandMap := map[string]int{}
	bandLabelMap := map[int]string{0: "2.4 GHz", 1: "5 GHz", 2: "6 GHz"}

	// Get the available Radio indices from capabilityMap
	availableRadioIndices := []int{}
	for band := range capabilityMap {
		availableRadioIndices = append(availableRadioIndices, band)
	}
	sort.Ints(availableRadioIndices)

	// Get the band name from availableRadioIndices
	for _, bandID := range availableRadioIndices {
		label := bandLabelMap[bandID]
		bandOptions = append(bandOptions, label)
		bandMap[label] = bandID
	}

	// dilogbox popup for channel config
	var dlg *widget.PopUp

	//Store Selected channels per class
	var channelCheckboxes map[string]*widget.Check

	// Widgets to be toggled
	channelDropdown := widget.NewSelect([]string{}, nil)
	channelDropdown.PlaceHolder = "Select a class"

	// Wrap dropdown to enforce width
	dropdownWrapped := container.NewGridWrap(fyne.NewSize(300, channelDropdown.MinSize().Height))
	dropdownWrapped.Add(channelDropdown)
	channelDropdownForm := container.NewHBox(
		widget.NewLabel("Choose Class:"),
		dropdownWrapped,
	)
	channelDropdownForm.Hide()

	// Channel checkboxes in dynamic grid
	operatingChannelList := container.NewVBox()
	channelSelectSection := container.NewVBox(
		widget.NewLabel("Select Channels:"),
		operatingChannelList,
	)
	channelSelectSection.Hide()

	//band group for band selection
	bandSelector := widget.NewRadioGroup(bandOptions, func(selected string) {
		var err error
		var selectedClass int
		showChannelCheckbox := false

		selectedBand := bandMap[selected]

		log.Printf("Selected Band: %s (ID: %d)", selected, selectedBand)

		// Get the availble class for the selected band
		classList := []string{}
		if capabilities, ok := capabilityMap[selectedBand]; ok {
			for _, cap := range capabilities {
				classList = append(classList, strconv.Itoa(cap.class))
			}
		}

		newDropDown := widget.NewSelect(classList, func(class string) {
			channelSelectSection.Show()

			selectedClass, err = strconv.Atoi(class)
			if err != nil {
				log.Printf("Invalid seleted class")
				return
			}

			var availableChannel []int
			for _, cap := range capabilityMap[selectedBand] {
				if cap.class == selectedClass {
					availableChannel = cap.channelList
					break
				}
			}

			// Get the previous configure channel for this class
			var configuredChannels []int
			for _, cfg := range prevConfigMap {
				if cfg.radioIndex == selectedBand && cfg.class == selectedClass {
					configuredChannels = cfg.channles
					break
				}
			}

			// Reset the map on chaning the class
			if prevSelectedBand == selectedBand {
				resetBandToSingleClass(selectedBand, selectedClass)
			}

			operatingChannelList.Objects = nil

			if len(availableChannel) > 0 {
				showChannelCheckbox = true
			}

			channelCheckboxes = map[string]*widget.Check{}
			var boxes []fyne.CanvasObject

			for _, ch := range availableChannel {
				label := strconv.Itoa(ch)
				check := widget.NewCheck(label, func(b bool) {
					updateChannelSection(selectedBand, selectedClass, ch, b)
				})

				selected := selectedChannelmap[selectedBand][selectedClass]
				if len(selected) > 0 {
					if selected[ch] {
						check.SetChecked(true)
					}
				} else {
					if contains(configuredChannels, ch) {
						for _, prevConfigChannel := range configuredChannels {
							check.SetChecked(true)
							updateChannelSection(selectedBand, selectedClass, prevConfigChannel, true)
						}
					}
				}
				channelCheckboxes[label] = check
				boxes = append(boxes, check)
			}

			cols := int(math.Ceil(math.Sqrt(float64(len(boxes)))))
			if cols < 1 {
				cols = 1
			}

			grid := container.New(layout.NewAdaptiveGridLayout(cols), boxes...)
			//grid := container.NewGridWithColumns(3, boxes...)
			operatingChannelList.Objects = []fyne.CanvasObject{grid}
			operatingChannelList.Refresh()
			channelSelectSection.Show()
		})

		// Select the previously configured class by default
		newDropDown.PlaceHolder = "Select a class"
		configuredClass := selectedChannelmap[selectedBand]
		if len(configuredClass) > 0 {
			for classVal := range configuredClass {
				newDropDown.SetSelected(strconv.Itoa(classVal))
			}
		} else {
			for _, cfg := range prevConfigMap {
				if cfg.radioIndex == selectedBand {
					selectedClass = cfg.class
					newDropDown.SetSelected(strconv.Itoa(selectedClass))
				}
			}
		}

		prevSelectedBand = selectedBand
		dropdownWrapped.Objects = []fyne.CanvasObject{newDropDown}
		dropdownWrapped.Resize(fyne.NewSize(300, newDropDown.MinSize().Height))
		dropdownWrapped.Refresh()
		channelDropdownForm.Show()
		channelDropdownForm.Refresh()
		if showChannelCheckbox == false {
			channelSelectSection.Hide()
		}
	})
	bandSelector.Horizontal = true
	bandSelector.SetSelected("2.4 GHz")
	channelDropdown.Refresh()

	// Action buttons
	applyBtn := widget.NewButton("Apply", func() {

		//update the  wifiChannel tree
		updateAnticipatedChannelPreference(wifiChannelUpdateTree)

		//Apply setting to update the channel
		applyChannelConfig(wifiChannelUpdateTree)

		// clear the channelmap
		selectedChannelmap = map[int]map[int]map[int]bool{}

		m.isEditing = false
		dlg.Hide()
	})

	// Cancel button
	cancelBtn := widget.NewButton("Cancel", func() {
		m.isEditing = false
		selectedChannelmap = map[int]map[int]map[int]bool{}
		dlg.Hide()
	})

	// Dialog content
	dialogContent := container.NewVBox(
		widget.NewLabelWithStyle("Wi-Fi Channel Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Select Band(s):"),
		bandSelector,
		channelDropdownForm,
		channelSelectSection,
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), applyBtn, cancelBtn),
	)

	dialogContent.Refresh()
	dlg = widget.NewModalPopUp(dialogContent, m.meshWindow.Canvas())
	dlg.Resize(fyne.NewSize(600, dialogContent.MinSize().Height))
	dlg.Show()
}

//------------------------------------------------------------
//                    Helper Functions
//--------------------------------------------------------------

/* func: getChannelCapabilityFromTree()
 * Description:
 * It parse the channel capability tree and fetch the list of channels
 * with respect to class and band
 * returns: array of classChannelMap
 */
func getChannelCapabilityFromTree(tree *C.em_network_node_t) map[int][]classChannelMap {

	isDuplicateEntries := false
	capabilityMap := make(map[int][]classChannelMap)

	if tree == nil || tree.num_children == 0 {
		return capabilityMap
	}

	radioListKey := C.CString("RadioList")
	capabilityKey := C.CString("ChannelCapability")
	defer C.free(unsafe.Pointer(radioListKey))
	defer C.free(unsafe.Pointer(capabilityKey))

	for i := 0; i < int(tree.num_children); i++ {
		item := tree.child[i]
		if item == nil {
			continue
		}

		radioListNode := C.get_network_tree_by_key(item, radioListKey)
		if radioListNode == nil || radioListNode.num_children == 0 {
			continue
		}

		//loop through all the radios
		for r := 0; r < int(radioListNode.num_children); r++ {
			radio := radioListNode.child[r]
			if radio == nil {
				continue
			}
			capabilityNode := C.get_network_tree_by_key(radio, capabilityKey)
			if capabilityNode == nil || capabilityNode.num_children == 0 {
				continue
			}

			// loop through the node and parse the necessary data
			for j := 0; j < int(capabilityNode.num_children); j++ {
				capabilityChild := capabilityNode.child[j]
				bandVal := getKeyIntValue(capabilityChild, "Band")
				classVal := getKeyIntValue(capabilityChild, "Class")
				existing := capabilityMap[bandVal]
				for _, cap := range existing {
					if cap.class == classVal {
						isDuplicateEntries = true
						break
					}
				}

				if isDuplicateEntries {
					continue
				}
				nonOperableNode := C.get_network_tree_by_key(capabilityChild, C.CString("NonOperable"))

				var nonOperable []int
				if nonOperableNode != nil {
					for k := 0; k < int(nonOperableNode.num_children); k++ {
						nonOperable = append(nonOperable, int(nonOperableNode.child[k].value_int))
					}
				}

				channelListNode := C.get_network_tree_by_key(capabilityChild, C.CString("ChannelList"))

				var channelList []int
				if channelListNode != nil {
					for k := 0; k < int(channelListNode.num_children); k++ {
						ch := int(channelListNode.child[k].value_int)
						if contains(nonOperable, ch) {
							continue
						}
						channelList = append(channelList, int(channelListNode.child[k].value_int))
					}
				}

				capability := classChannelMap{
					class:       classVal,
					channelList: channelList,
				}
				capabilityMap[bandVal] = append(capabilityMap[bandVal], capability)
			}
		}
	}
	return capabilityMap
}

/* func: getConfiguredChannels()
 * Description:
 * It parse the current channel tree and get the list of current
 * channels with respect to class and band
 * returns: array of channelConfig
 */
func getConfiguredChannels(tree *C.em_network_node_t) []channelConfig {
	var result []channelConfig

	// Get the AnticipatedChannelPreference
	configuredChannelPrefNode := C.get_network_tree_by_key(tree, C.CString("AnticipatedChannelPreference"))
	if configuredChannelPrefNode == nil {
		log.Printf("Failed to get previous channel configuration")
		return result
	}

	// Get the list of configured class with respect to class and band
	for i := 0; i < int(configuredChannelPrefNode.num_children); i++ {
		configuredChannel := configuredChannelPrefNode.child[i]
		ConfigClass := getKeyIntValue(configuredChannel, "Class")
		configChannelList := C.get_network_tree_by_key(configuredChannel, C.CString("ChannelList"))

		var configChannels []int
		if configChannelList != nil {
			for j := 0; j < int(configChannelList.num_children); j++ {
				configChannels = append(configChannels, int(configChannelList.child[j].value_int))
			}
		}
		result = append(result, channelConfig{
			radioIndex: i,
			class:      ConfigClass,
			channles:   configChannels,
		})

	}

	return result
}

/* func: updateChannelSection()
 * Description:
 * It create a map of current selected channel list with respect to
 * class and band
 * returns: array of selectedChannelmap
 */
func updateChannelSection(band, class, channel int, selected bool) {
	if selectedChannelmap[band] == nil {
		selectedChannelmap[band] = map[int]map[int]bool{}
	}

	if selectedChannelmap[band][class] == nil {
		selectedChannelmap[band][class] = map[int]bool{}
	}

	if selected {
		selectedChannelmap[band][class][channel] = true
	} else {
		// remove the channe; if unchecked
		delete(selectedChannelmap[band][class], channel)

		if len(selectedChannelmap[band][class]) == 0 {
			delete(selectedChannelmap[band], class)
		}

		if len(selectedChannelmap[band]) == 0 {
			delete(selectedChannelmap, class)
		}
	}
}

/* func: resetBandToSingleClass()
 * Description:
 * Reset the current selectedChannelmap if class changed
 * returns: N/A
 */
func resetBandToSingleClass(band, class int) {
	selectedChannelmap[band] = map[int]map[int]bool{
		class: {},
	}
}

/* func: updateAnticipatedChannelPreference()
 * Description:
 * parse and update the AnticipatedChannelPreference
 * returns: N/A
 */
func updateAnticipatedChannelPreference(tree *C.em_network_node_t) {
	if tree == nil {
		log.Printf("Invalid channel update tree")
	}

	channelPrefTree_cmd := C.CString("AnticipatedChannelPreference")
	classNode_cmd := C.CString("Class")
	defer C.free(unsafe.Pointer(channelPrefTree_cmd))
	defer C.free(unsafe.Pointer(classNode_cmd))
	channelPrefTree := C.get_network_tree_by_key(tree, channelPrefTree_cmd)

	for bandIndex, classMap := range selectedChannelmap {
		for classValue, channels := range classMap {
			channelPrefNode := channelPrefTree.child[bandIndex]
			classNode := C.get_network_tree_by_key(channelPrefNode, classNode_cmd)
			if classNode != nil {
				classNode.value_int = C.uint(classValue)
			}
			channelListNode := C.get_network_tree_by_key(channelPrefNode, C.CString("ChannelList"))
			C.set_node_type(channelListNode, C.em_network_node_data_type_array_num)
			channelListNode.num_children = 0
			C.set_node_array_value(channelListNode, C.CString(mapchannelsToSlice(channels)))

		}
	}

}

/* func: applyChannelConfig()
 * Description:
 * Executes the set ssid set_channel on the update channel list
 * returns: true for successfully executed, otherwise false.
 */
func applyChannelConfig(ssidTree *C.em_network_node_t) bool {
	resultKey := C.CString("Result")
	cmd := C.CString("set_channel OneWifiMesh")
	defer C.free(unsafe.Pointer(resultKey))
	defer C.free(unsafe.Pointer(cmd))

	// get the node for Set channel tree
	set_channel_node := C.get_network_tree_by_key(ssidTree, resultKey)
	if set_channel_node == nil {
		log.Println("result node not found")
		return false
	}

	//Execute the set_channel command with updated chanelList
	C.exec(cmd, C.strlen(cmd), set_channel_node)
	return true
}

/* func: mapchannelsToSlice()
 * Description:
 * Convert the channelmap to string
 * returns: channel list array in string format
 */
func mapchannelsToSlice(m map[int]bool) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	strKeys := make([]string, len(keys))
	for i, val := range keys {
		strKeys[i] = strconv.Itoa((val))
	}
	return "[" + strings.Join(strKeys, ", ") + "]"
}

/* func: getKeyIntValue()
 * Description:
 * get the int value from node key
 * returns: int value of node.
 */
func getKeyIntValue(tree *C.em_network_node_t, key string) int {
	node := C.get_network_tree_by_key(tree, C.CString(key))
	if node != nil {
		switch C.get_node_type(node) {
		case C.em_network_node_data_type_number:
			return int(node.value_int)
		}

	}
	return 0
}

/* func: contains()
 * Description:
 * helper function to check the value from array
 * returns: int value of node.
 */
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

/* func: periodicTimer()
 * Description:
 * Periodic timer function to refresh the wifi channel tab based on timer.
 * Returns: NA
 */
func (s *WifiChannel) periodicTimer() {
	s.obj.Refresh()
}

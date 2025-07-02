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

	//"fyne.io/fyne/layout"

	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

/* func: ShowWifiResetDialog()
 * Description:
 * Create a dialog box to configure wifi reset
 * returns: NA
 */
func ShowWifiResetDialog(m *MeshViewsMgr) {
    meshViewsMgr.isEditing = true
    resetTree := C.exec(C.CString("get_reset OneWifiMesh"), C.strlen(C.CString("get_reset OneWifiMesh")), nil)
    if resetTree == nil {
        log.Println("Failed to fetch reset tree")
        return
    }

    // Basic field retrieval
    idValue := getTreeValue(resetTree, "ID")
    deviceCountValue := getTreeValue(resetTree, "NumberOfDevices")
    timeStampValue := getTreeValue(resetTree, "TimeStamp")
    ControllerIDValue := getTreeValue(resetTree, "ControllerID")
    collocatedValue := getTreeValue(resetTree, "CollocatedAgentID")
    mediaType := getTreeValue(resetTree, "MediaType")

    // Assuming deviceCountValue is a string
    deviceCountInt, err := strconv.Atoi(deviceCountValue)
    if err != nil {
        deviceCountInt = 0
    }
    countStr := fmt.Sprintf("%d", deviceCountInt)

    // Interface MACs
    interfacesList := C.get_network_tree_by_key(resetTree, C.CString("List"))
    macOptions := getInterfacePrefence(interfacesList)
    macOptions = append(macOptions, "Other")

    manualMacEntry := widget.NewEntry()
    manualMacEntry.SetPlaceHolder("Enter MAC address")
    // hidden until "Other" is selected
    manualMacEntry.Hide()

    collocatedSelect := widget.NewSelect(macOptions, func(selected string) {
        log.Printf("Selected CollocatedAgentID: %s", selected)
        if selected == "Other" {
            manualMacEntry.Show()
        } else {
            manualMacEntry.Hide()
        }
    })

    collocatedSelect.PlaceHolder = "Choose or update MAC"
    for _, opt := range macOptions {
        if strings.HasPrefix(opt, collocatedValue) {
            collocatedSelect.SetSelected(opt)
            break
        }
    }

    // Haul type selection
    haulTypes := getAllHaulTypes(resetTree)
    selectedHauls := widget.NewCheckGroup(haulTypes, nil)

    ssidEntries := make(map[string]*widget.Entry)
    passEntries := make(map[string]*widget.Entry)
    bandEntries := make(map[string]fyne.CanvasObject)
    akmsAllowedEntries := make(map[string]fyne.CanvasObject)
    suiteSelectorEntries := make(map[string]fyne.CanvasObject)
    mfpConfigEntries := make(map[string]fyne.CanvasObject)
    mobilityDomainEntries := make(map[string]fyne.CanvasObject)
    enableEntries := make(map[string]fyne.CanvasObject)
    advertisementEnabled := make(map[string]fyne.CanvasObject)
    haulForms := container.NewVBox()

    haulData := getConfiguredHauls(resetTree)

    selectedHauls.OnChanged = func(selected []string) {
        haulForms.Objects = nil
        for _, haul := range selected {
            config := haulData[haul]
            ssid := widget.NewEntry()
            ssid.SetPlaceHolder(fmt.Sprintf("%s SSID", haul))
            ssid.SetText(config["SSID"])

            pass := widget.NewEntry()
            pass.SetPlaceHolder(fmt.Sprintf("%s PassPhrase", haul))
            pass.SetText(config["PassPhrase"])

            band := widget.NewLabel(config["Band"])
            akmsAllowed := widget.NewLabel(config["AKMsAllowed"])
            suiteSelector := widget.NewLabel(config["SuiteSelector"])
            mfpConfig := widget.NewLabel(config["MFPConfig"])
            mobilityDomain := widget.NewLabel(config["MobilityDomain"])
            enable := widget.NewLabel(config["Enable"])
            advertisement := widget.NewLabel(config["AdvertisementEnabled"])

            ssidEntries[haul] = ssid
            passEntries[haul] = pass
            bandEntries[haul] = band
            enableEntries[haul] = enable
            akmsAllowedEntries[haul] = akmsAllowed
            suiteSelectorEntries[haul] = suiteSelector
            advertisementEnabled[haul] = advertisement
            mfpConfigEntries[haul] = mfpConfig
            mobilityDomainEntries[haul] = mobilityDomain

            form := widget.NewForm(
                widget.NewFormItem("SSID", ssid),
                widget.NewFormItem("PassPhrase", pass),
                widget.NewFormItem("Band", band),
                widget.NewFormItem("AKMsAllowed", akmsAllowed),
                widget.NewFormItem("SuiteSelector", suiteSelector),
                widget.NewFormItem("Enable", enable),
                widget.NewFormItem("AdvertisementEnabled", advertisement),
                widget.NewFormItem("MFPConfig", mfpConfig),
                widget.NewFormItem("MobilityDomain", mobilityDomain),
            )

            haulForms.Add(container.NewVBox(
                widget.NewLabelWithStyle(fmt.Sprintf("%s Configuration", haul), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
                form,
            ))
        }
        haulForms.Refresh()
    }

    var dlg *widget.PopUp
    scrollContent := container.NewVBox(
        widget.NewLabelWithStyle("WiFi Reset Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
        widget.NewForm(
            widget.NewFormItem("ID", widget.NewLabel(idValue)),
            widget.NewFormItem("NumberOfDevices", widget.NewLabel(countStr)),
            widget.NewFormItem("TimeStamp", widget.NewLabel(timeStampValue)),
            widget.NewFormItem("ControllerID", widget.NewLabel(ControllerIDValue)),
            widget.NewFormItem("CollocatedAgentID", container.NewVBox(
                collocatedSelect,
                manualMacEntry,
            )),
            widget.NewFormItem("MediaType", widget.NewLabel(mediaType)),
            widget.NewFormItem("Haul Type(s)", selectedHauls),
        ),
        haulForms,
        layout.NewSpacer(),
        container.NewHBox(
            layout.NewSpacer(),
            widget.NewButton("Apply", func() {
                valid := true
                errorsList := []string{}
                selectedMac := collocatedSelect.Selected
                if selectedMac == "Other" {
                    selectedMac = manualMacEntry.Text
                } else if parts := strings.Split(selectedMac, " "); len(parts) > 0 {
                    selectedMac = parts[0]
                }
                // First, update SSID and PassPhrase fields into resetTree
                for haul, ssidEntry := range ssidEntries {
                    ssid := strings.TrimSpace(ssidEntry.Text)
                    pass := strings.TrimSpace(passEntries[haul].Text)

                    // validate the SSID before setting
                    if err := validateSSID(ssid); err != nil {
                        msg := fmt.Sprintf("Invalid SSID for haul '%s': %v", haul, err)
                        errorsList = append(errorsList, msg)
                        valid = false
                        continue
                    }

                    // validate the passphase before setting
                    if err := validatePassPhrase(pass); err != nil {
                        msg := fmt.Sprintf("Invalid PassPhrase for haul '%s': %v", haul, err)
                        errorsList = append(errorsList, msg)
                        valid = false
                        continue
                    }

                    if err := updateSSIDPassForHaulType(resetTree, haul, ssid, pass); err != nil {
                        msg := fmt.Sprintf("Update failed for SSID and PassPhrase on haul '%s': %v", haul, err)
                        errorsList = append(errorsList, msg)
                        valid = false
                    }
                }

                // update the CollocatedAgentID in reset tree
                if err := updateCollocatedAgentID(resetTree, selectedMac); err != nil {
                    msg := fmt.Sprintf("Update failed for CollocatedAgentID: %v", err)
                    errorsList = append(errorsList, msg)
                    valid = false
                }

                if !valid && err != nil {
                    fullError := fmt.Errorf("ERROR: %s", strings.Join(errorsList, "\n"))
                    dialog.ShowError(fullError, m.meshWindow)
                    return
                }

                //fmt.Println("---- UPDATED RESET TREE BEFORE APPLY ----")
                //printTree(resetTree, 0)
                //fmt.Println("-----------------------------------------")
                dialog.ShowConfirm(
                    "Confirm WiFi Reset",
                    "Resetting the WiFi configuration may require the controller to restart.\nDo you want to continue?",
                    func(confirm bool) {
                        if confirm {
                            // User pressed OK → proceed
                            applyResetConfig(resetTree)
                            meshViewsMgr.isEditing = false
                            dlg.Hide()
                        } else {
                            // User pressed Cancel → do nothing
                            log.Println("User cancelled WiFi reset.")
                        }
                    },
                    m.meshWindow,
                )
            }),
            widget.NewButton("Cancel", func() {
                meshViewsMgr.isEditing = false
                dlg.Hide()
            }),
        ),
    )

    dlg = widget.NewModalPopUp(
        container.NewVScroll(scrollContent),
        m.meshWindow.Canvas(),
    )
    dlg.Resize(fyne.NewSize(520, 500))
    dlg.Show()
}

//------------------------------------------------------------
//                    Helper Functions
//--------------------------------------------------------------

/* func: printTree()
 * Description:
 * Print the tree for debug purpose
 * returns: NA.
 */
func printTree(node *C.em_network_node_t, indent int) {
    if node == nil {
        return
    }

    prefix := strings.Repeat("  ", indent)
    key := C.GoString(&node.key[0])
    value := C.GoString(&node.value_str[0])
    fmt.Printf("%s%s: %s\n", prefix, key, value)

    for i := 0; i < int(node.num_children); i++ {
        printTree(node.child[i], indent+1)
    }
}

/* func: getInterfacePrefence()
 * Description:
 * It recursively traverses the provided em_network_node_t tree
 * and extracts all string values representing interface MAC addresses.
 * It supports nested arrays and objects.
 * returns: list of MAC strings.
 */
func getInterfacePrefence(tree *C.em_network_node_t) []string {
    var macList []string

    if tree == nil {
        return macList
    }

    nodeType := C.get_node_type(tree)
    if nodeType == C.em_network_node_data_type_array_obj ||
        nodeType == C.em_network_node_data_type_array_num ||
        nodeType == C.em_network_node_data_type_array_str ||
        nodeType == C.em_network_node_data_type_obj {
        for i := 0; i < int(tree.num_children); i++ {
            childMacs := getInterfacePrefence(tree.child[i])
            macList = append(macList, childMacs...)
        }
    } else if nodeType == C.em_network_node_data_type_string {
        mac := C.GoString(&tree.value_str[0])
        macList = append(macList, mac)
    }

    return macList
}

/* func: getAllHaulTypes()
 * Description:
 * Traverses the "NetworkSSIDList" node in the provided em_network_node_t tree,
 * and collects all HaulType values from each SSID entry. Supports multiple
 * haul types per entry.
 * returns: list of haul type strings (e.g. "Fronthaul", "Backhaul", etc.).
 */
func getAllHaulTypes(tree *C.em_network_node_t) []string {
    var haulTypes []string
    listNode := C.get_network_tree_by_key(tree, C.CString("NetworkSSIDList"))
    if listNode == nil {
        return haulTypes
    }

    for i := 0; i < int(listNode.num_children); i++ {
        node := listNode.child[i]
        haulTypeNode := C.get_network_tree_by_key(node, C.CString("HaulType"))
        if haulTypeNode == nil || int(haulTypeNode.num_children) == 0 {
            continue
        }

        // Iterate over all HaulType values
        for j := 0; j < int(haulTypeNode.num_children); j++ {
            haul := C.GoString(&haulTypeNode.child[j].value_str[0])
            haulTypes = append(haulTypes, haul)
        }
    }

    return haulTypes
}

/* func: getConfiguredHauls()
 * it extracts WiFi haul configurations from the given network tree.
 * Returns: nested map: haulType → {configKey → value}
 */
func getConfiguredHauls(tree *C.em_network_node_t) map[string]map[string]string {
    haulConfigs := make(map[string]map[string]string)
    listNode := C.get_network_tree_by_key(tree, C.CString("NetworkSSIDList"))
    if listNode == nil {
        return haulConfigs
    }

    for i := 0; i < int(listNode.num_children); i++ {
        node := listNode.child[i]

        // Handle HaulType as list
        haulTypeNode := C.get_network_tree_by_key(node, C.CString("HaulType"))
        if haulTypeNode == nil || int(haulTypeNode.num_children) == 0 {
            continue
        }

        haul := C.GoString(&haulTypeNode.child[0].value_str[0])
        config := map[string]string{
            "SSID":                 getTreeValue(node, "SSID"),
            "PassPhrase":           getTreeValue(node, "PassPhrase"),
            "Enable":               getTreeValue(node, "Enable"),
            "SuiteSelector":        getTreeValue(node, "SuiteSelector"),
            "AdvertisementEnabled": getTreeValue(node, "AdvertisementEnabled"),
            "MFPConfig":            getTreeValue(node, "MFPConfig"),
            "MobilityDomain":       getTreeValue(node, "MobilityDomain"),
        }

        // Handle array fields
        if bandNode := C.get_network_tree_by_key(node, C.CString("Band")); bandNode != nil {
            config["Band"] = joinArrayValues(bandNode)
        }
        if akmNode := C.get_network_tree_by_key(node, C.CString("AKMsAllowed")); akmNode != nil {
            config["AKMsAllowed"] = joinArrayValues(akmNode)
        }
        if enableNode := C.get_network_tree_by_key(node, C.CString("Enable")); enableNode != nil {
            config["Enable"] = getTreeValue(node, "Enable")
        }

        haulConfigs[haul] = config
    }

    return haulConfigs
}

/* func: updateSSIDPassForHaulType()
 * Description:
 * Searches the NetworkSSIDList for a matching HaulType and updates its SSID and PassPhrase fields.
 * returns: nil on successful update; otherwise an error if the list or matching HaulType is not found.
 */
func updateSSIDPassForHaulType(resetTree *C.em_network_node_t, haulType, newSSID, newPass string) error {
    networkKey := C.CString("NetworkSSIDList")
    defer C.free(unsafe.Pointer(networkKey))

    ssidListNode := C.get_network_tree_by_key(resetTree, networkKey)
    if ssidListNode == nil {
        return fmt.Errorf("NetworkSSIDList node not found in reset tree")
    }

    for i := 0; i < int(ssidListNode.num_children); i++ {
        item := ssidListNode.child[i]
        if item == nil {
            continue
        }

        haulKey := C.CString("HaulType")
        haulNode := C.get_network_tree_by_key(item, haulKey)
        C.free(unsafe.Pointer(haulKey))
        if haulNode == nil || int(haulNode.num_children) == 0 {
            continue
        }

        haulTypeStr := C.GoString(&haulNode.child[0].value_str[0])
        if strings.Contains(haulTypeStr, haulType) {
            updateNodeValue(item, "SSID", newSSID)
            updateNodeValue(item, "PassPhrase", newPass)
        }
    }
    return nil
}

/* func: applyResetConfig
 * Description:
 * updates the CollocatedAgentID value in the given reset configuration tree
 * based on the selected or manually entered MAC address, validates its format,
 * and executes the reset command to apply the updated configuration.
 * Return: true or false
 */
func updateCollocatedAgentID(resetTree *C.em_network_node_t, selectedMac string) error {
    if !isValidMac(selectedMac) {
        return fmt.Errorf("invalid MAC address: %s", selectedMac)
    }

    cMac := C.CString(selectedMac)
    cKey := C.CString("CollocatedAgentID")
    defer C.free(unsafe.Pointer(cMac))
    defer C.free(unsafe.Pointer(cKey))

    node := C.get_network_tree_by_key(resetTree, cKey)
    if node == nil {
        return fmt.Errorf("CollocatedAgentID node not found in reset tree")
    }

    buf := (*[256]byte)(unsafe.Pointer(&node.value_str[0]))
    for i := range buf {
        buf[i] = 0
    }
    copy(buf[:], selectedMac)

    return nil
}

/* func: applyResetConfig()
 * Description:
 * Executes the WiFi reset command on the configuration tree by locating the
 * "wfa-dataelements:Reset" node and invoking the associated reset operation.
 * returns: true if the reset command was successfully executed, otherwise false.
 */
func applyResetConfig(resetTree *C.em_network_node_t) bool {
    resetKey := C.CString("wfa-dataelements:Reset")
    cmd := C.CString("reset OneWifiMesh")
    defer C.free(unsafe.Pointer(resetKey))
    defer C.free(unsafe.Pointer(cmd))

    resetNode := C.get_network_tree_by_key(resetTree, resetKey)
    if resetNode == nil {
        log.Println("Reset node not found")
        return false
    }

    C.exec(cmd, C.strlen(cmd), resetNode)
    return true
}

/* func: isValidMac()
 * Description:
 * Validates whether the given string is a properly formatted MAC address.
 * returns: true for MAC address format, otherwise false.
 */
func isValidMac(mac string) bool {
    // Normalize to lowercase and remove interface name, if present
    mac = strings.Split(mac, " ")[0]

    // MAC format: 6 pairs of hex digits separated by colons
    re := regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
    return re.MatchString(mac)
}

/* func: joinArrayValues()
 * Description: converts an array-type em_network_node_t into a single comma-separated string.
 * Return: A single string containing all child string values joined with ", ".
 */
func joinArrayValues(node *C.em_network_node_t) string {
    values := []string{}
    for i := 0; i < int(node.num_children); i++ {
        val := C.GoString(&node.child[i].value_str[0])
        values = append(values, val)
    }
    return strings.Join(values, ", ")
}

/* func: getTreeValue()
 * Description: helper function to get value for respective key
 * Return: value of key in String format.
 */
func getTreeValue(tree *C.em_network_node_t, key string) string {
    node := C.get_network_tree_by_key(tree, C.CString(key))
    if node != nil {
        switch C.get_node_type(node) {
        case C.em_network_node_data_type_string:
            return C.GoString(&node.value_str[0])
        case C.em_network_node_data_type_false:
            return "false"
        case C.em_network_node_data_type_true:
            return "true"
        }
    }
    return ""
}

/* func: updateNodeValue()
 * Description: helper function to set the updated node value
 * Return: NA
 */
func updateNodeValue(parent *C.em_network_node_t, key, newVal string) {
    cKey := C.CString(key)
    defer C.free(unsafe.Pointer(cKey))

    node := C.get_network_tree_by_key(parent, cKey)
    if node == nil {
        log.Printf("Key '%s' not found in tree", key)
        return
    }

    // Safely zero out and copy string into fixed-size buffer
    const bufSize = 256
    buf := (*[bufSize]byte)(unsafe.Pointer(&node.value_str[0]))

    for i := range buf {
        buf[i] = 0
    }
    copy(buf[:], newVal)
}

/* func: validateSSID()
 * Description: helper function to validate the ssid name
 * Return: NA
 */
func validateSSID(ssid string) error {
    if ssid == "" {
        return fmt.Errorf("SSID cannot be empty")
    }
    if len(ssid) > 32 {
        return fmt.Errorf("SSID must be 32 characters or fewer")
    }
    if matched, _ := regexp.MatchString(`^[\w\-\. ]+$`, ssid); !matched {
        return fmt.Errorf("SSID contains invalid characters")
    }
    return nil
}

/* func: validatePassPhrase()
 * Description: helper function to validate the passphase
 * Return: NA
 */
func validatePassPhrase(pass string) error {
    if pass == "" {
        return fmt.Errorf("PassPhrase cannot be empty")
    }
    if len(pass) < 8 || len(pass) > 63 {
        return fmt.Errorf("PassPhrase must be 8-63 characters")
    }
    return nil
}

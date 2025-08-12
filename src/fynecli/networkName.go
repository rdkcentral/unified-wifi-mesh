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
	"log"
	"regexp"
	"strings"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// haulConfig struct
type HaulConfig struct {
    Haul string
    SSID string
    PassPhrase string
}

/* func: ShowNetworkNameDialog()
 * Description:
 * Create a dialog box to configure wifi Network name
 * Returns: NA
 */
func ShowNetworkNameDialog(m *MeshViewsMgr) {
    meshViewsMgr.isEditing = true

    // Get SSID tree
    ssidTree := C.exec(C.CString("get_ssid OneWifiMesh"), C.strlen(C.CString("get_ssid OneWifiMesh")), nil)
    if ssidTree == nil {
        log.Println("Failed to fetch network name tree")
        return
    }

    // Get all the available haul type
    haulData := getConfiguredHauls(ssidTree)
    if len(haulData) == 0 {
        dialog.ShowInformation("Info", "No haul configuration found", m.meshWindow)
        return
    }

    type HaulConfigEntry struct {
        SSID       string
        PassPhrase string
    }

    // used during Apply
    haulInputs := map[string]HaulConfigEntry{}

    // used for comparison before Apply
    originalHaulInputs := map[string]HaulConfigEntry{}

    haulOptions := make([]string, 0, len(haulData))
    for _, config := range haulData {
        entry := HaulConfigEntry{config.SSID, config.PassPhrase}
        haulInputs[config.Haul] = entry
        originalHaulInputs[config.Haul] = entry
        haulOptions = append(haulOptions, config.Haul)
    }

    selectedHaul := haulOptions[0]
    ssidEntry := widget.NewEntry()
    passEntry := widget.NewEntry()
    ssidEntry.SetText(originalHaulInputs[selectedHaul].SSID)
    passEntry.SetText(originalHaulInputs[selectedHaul].PassPhrase)

    modifiedHauls := map[string]bool{}
    modifiedLabel := widget.NewLabel("Updated Haul Types: none")

    isModified := func(original, current HaulConfigEntry) bool {
        return original.SSID != current.SSID || original.PassPhrase != current.PassPhrase
    }

    updateModifiedLabel := func() {
        if isModified(originalHaulInputs[selectedHaul], HaulConfigEntry{ssidEntry.Text, passEntry.Text}) {
            modifiedHauls[selectedHaul] = true
        } else {
            delete(modifiedHauls, selectedHaul)
        }

        if len(modifiedHauls) == 0 {
            modifiedLabel.SetText("Updated Haul Types: none")
            return
        }

        updated := make([]string, 0, len(modifiedHauls))
        for h := range modifiedHauls {
            updated = append(updated, h)
        }
        modifiedLabel.SetText("Updated Haul Types: " + strings.Join(updated, ", "))
    }

    ssidEntry.OnChanged = func(_ string) { updateModifiedLabel() }
    passEntry.OnChanged = func(_ string) { updateModifiedLabel() }

    haulSelect := widget.NewSelect(haulOptions, func(value string) {
        current := HaulConfigEntry{ssidEntry.Text, passEntry.Text}
        if isModified(originalHaulInputs[selectedHaul], current) {
            haulInputs[selectedHaul] = current
            modifiedHauls[selectedHaul] = true
        }

        selectedHaul = value
        ssidEntry.SetText(haulInputs[value].SSID)
        passEntry.SetText(haulInputs[value].PassPhrase)
        updateModifiedLabel()
    })
    haulSelect.SetSelected(selectedHaul)

    var dlg *widget.PopUp
    applyBtn := widget.NewButton("Apply", func() {
        haulInputs[selectedHaul] = HaulConfigEntry{ssidEntry.Text, passEntry.Text}
        updateModifiedLabel()

        errors := []string{}
        for haul, updated := range modifiedHauls {
            if !updated {
                continue
            }
            entry := haulInputs[haul]
            if err := validateSSID(entry.SSID); err != nil {
                errors = append(errors, fmt.Sprintf("Invalid SSID for %s: %v", haul, err))
            }
            if err := validatePassPhrase(entry.PassPhrase); err != nil {
                errors = append(errors, fmt.Sprintf("Invalid PassPhrase for %s: %v", haul, err))
            }
        }

        if len(errors) > 0 {
            dialog.ShowError(fmt.Errorf("ERROR:\n%s", strings.Join(errors, "\n")), m.meshWindow)
            return
        }

        for haul := range modifiedHauls {
            entry := haulInputs[haul]
            if err := updateSSIDPassForHaulType(ssidTree, haul, entry.SSID, entry.PassPhrase); err != nil {
                dialog.ShowError(fmt.Errorf("Update failed for %s: %v", haul, err), m.meshWindow)
                return
            }
            originalHaulInputs[haul] = entry
        }

        applyNetworkNameConfig(ssidTree)
        meshViewsMgr.isEditing = false
        dlg.Hide()
    })

    cancelBtn := widget.NewButton("Cancel", func() {
        meshViewsMgr.isEditing = false
        dlg.Hide()
    })

    form := widget.NewForm(
        widget.NewFormItem("Haul Type", haulSelect),
        widget.NewFormItem("SSID", ssidEntry),
        widget.NewFormItem("PassPhrase", passEntry),
    )

    dialogContent := container.NewVBox(
        widget.NewLabelWithStyle("Edit SSID and PassPhrase per Haul Type", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
        form,
        modifiedLabel,
        container.NewHBox(layout.NewSpacer(), applyBtn, cancelBtn),
    )

    dlg = widget.NewModalPopUp(dialogContent, m.meshWindow.Canvas())
    dlg.Resize(fyne.NewSize(600, dialogContent.MinSize().Height))
    dlg.Show()
}

//------------------------------------------------------------
//                    Helper Functions
//--------------------------------------------------------------

/* func: getConfiguredHauls()
 * Description: it extracts WiFi haul configurations from the given network tree.
 * Returns: Array of HaulConfig
 */
func getConfiguredHauls(tree *C.em_network_node_t) []HaulConfig {
    var haulConfigs []HaulConfig
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
        config := HaulConfig{
            Haul: haul,
            SSID: getTreeValue(node, "SSID"),
            PassPhrase: getTreeValue(node, "PassPhrase"),
        }

        haulConfigs = append(haulConfigs, config)
    }

    return haulConfigs
}

/* func: updateSSIDPassForHaulType()
 * Description:
 * Searches the NetworkSSIDList for a matching HaulType and updates its SSID and PassPhrase fields.
 * returns: nil on successful update; otherwise an error if the list or matching HaulType is not found.
 */
func updateSSIDPassForHaulType(ssidTree *C.em_network_node_t, haulType, newSSID, newPass string) error {
    networkKey := C.CString("NetworkSSIDList")
    defer C.free(unsafe.Pointer(networkKey))

    ssidListNode := C.get_network_tree_by_key(ssidTree, networkKey)
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

/* func: applyNetworkNameConfig()
 * Description:
 * Executes the set ssid command on the update NetworkSSIDList with
 * updated ssid and phassphase.
 * returns: true if the reset command was successfully executed, otherwise false.
 */
func applyNetworkNameConfig(ssidTree *C.em_network_node_t) bool {
    networkSSIDKey := C.CString("Result")
    cmd := C.CString("set_ssid OneWifiMesh")
    defer C.free(unsafe.Pointer(networkSSIDKey))
    defer C.free(unsafe.Pointer(cmd))

    ssidNode := C.get_network_tree_by_key(ssidTree, networkSSIDKey)
    if ssidNode == nil {
        log.Println("NetworkSSIDList node not found")
        return false
    }

    C.exec(cmd, C.strlen(cmd), ssidNode)
    return true
}
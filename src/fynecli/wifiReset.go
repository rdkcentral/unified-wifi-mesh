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

    collocatedValue := getTreeValue(resetTree, "CollocatedAgentID")

    // Interface MACs
    interfacesList := C.get_network_tree_by_key(resetTree, C.CString("List"))
    macOptions := getInterfacePrefence(interfacesList)
    macOptions = append(macOptions, "Other")

    manualMacEntry := widget.NewEntry()
    manualMacEntry.SetPlaceHolder("Enter MAC address")
    // hidden until "Other" is selected
    manualMacEntry.Hide()

    collocatedSelect := widget.NewSelect(macOptions, func(selected string) {
        log.Printf("Selected AL_MAC Interface: %s", selected)
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

    var dlg *widget.PopUp
    resetDialogBody := container.NewVBox(
        widget.NewLabelWithStyle("WiFi Reset Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
        widget.NewForm(
            widget.NewFormItem("AL_MAC Interface", container.NewVBox(
                collocatedSelect,
                manualMacEntry,
            )),
        ),
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

                // update the CollocatedAgentID in reset tree
                err := updateCollocatedAgentID(resetTree, selectedMac)
                if err != nil {
                    msg := fmt.Sprintf("Update failed for AL_MAC Interface: %v", err)
                    errorsList = append(errorsList, msg)
                    valid = false
                }

                if !valid {
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
        resetDialogBody,
        m.meshWindow.Canvas(),
    )
    //dlg.Resize(fyne.NewSize(450, 200))
    dlg.Resize(dlg.Content.MinSize())
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


/* func: updateCollocatedAgentID
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
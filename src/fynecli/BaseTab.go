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
    "strings"
    "strconv"
    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/widget"
)

func (b *BaseTab) dumpNetNode(tree *C.em_network_node_t) {
    log.Printf("Key:\t%s\tType:%d", C.GoString(&tree.key[0]), int(C.get_node_type(tree)));
   
    nodeType := C.get_node_type(tree)
    
    if nodeType == C.em_network_node_data_type_array_obj || nodeType == C.em_network_node_data_type_array_num ||
                    nodeType == C.em_network_node_data_type_array_str{
        for i := 0; i < int(tree.num_children); i++ {
            b.dumpNetNode(tree.child[i])
        }
    } else if nodeType == C.em_network_node_data_type_obj {
        for i := 0; i < int(tree.num_children); i++ {
            b.dumpNetNode(tree.child[i])
        }
    } else if nodeType == C.em_network_node_data_type_string {
        log.Printf("Value:\t%s", C.GoString(&tree.value_str[0]));
    } else if nodeType == C.em_network_node_data_type_number {
        log.Printf("Value:\t%d", int(tree.value_int));
    } else if nodeType == C.em_network_node_data_type_false {
        log.Printf("Value:\tfalse");
    } else if nodeType == C.em_network_node_data_type_true {
        log.Printf("Value:\ttrue");
    }
}

func (b *BaseTab) children(id widget.TreeNodeID) []widget.TreeNodeID {
    var tree     *C.em_network_node_t
    var branch     *C.em_network_node_t
    var s []string
    var after string
    var index int

    index = -1
    tree = b.getData()

    if tree == nil {
        return []string{}
    }

    if id == "" {
        tree = C.get_network_tree_by_key(tree, C.CString("Result"))
    } else if strings.Contains(id, "[") && strings.Contains(id, "]") {
        id, after, _ = strings.Cut(id, "[")
        after, _, _ = strings.Cut(after, "]")
        index, _ = strconv.Atoi(after)
        tree = C.get_network_tree_by_key(tree, C.CString(id))
        if index != -1 {
            tree = tree.child[index]
        }
    } else {
        tree = C.get_network_tree_by_key(tree, C.CString(id))
    }

    if tree == nil {
        log.Printf("tree nil for id: %s", id)
        return []string{}
    }

    nodeType := C.get_node_type(tree)

    if nodeType == C.em_network_node_data_type_obj {
        for i := 0; i < int(tree.num_children); i++ {
            branch = tree.child[i]
            nodeType = C.get_node_type(branch)
            if nodeType == C.em_network_node_data_type_string {
                s = append(s, fmt.Sprintf("%s: %s", C.GoString(&branch.key[0]), C.GoString(&branch.value_str[0])))
            } else if nodeType == C.em_network_node_data_type_number {
                s = append(s, fmt.Sprintf("%s: %d", C.GoString(&branch.key[0]), int(branch.value_int)))
            } else if nodeType == C.em_network_node_data_type_false {
                s = append(s, fmt.Sprintf("%s: false", C.GoString(&branch.key[0])))
            } else if nodeType == C.em_network_node_data_type_true {
                s = append(s, fmt.Sprintf("%s: true", C.GoString(&branch.key[0])))
            } else if nodeType == C.em_network_node_data_type_array_obj {
                s = append(s, fmt.Sprintf("%s", C.GoString(&branch.key[0])))
            } else if nodeType == C.em_network_node_data_type_array_str {
                s = append(s, fmt.Sprintf("%s", C.GoString(&branch.key[0])))
            } else if nodeType == C.em_network_node_data_type_array_num {
                s = append(s, fmt.Sprintf("%s", C.GoString(&branch.key[0])))
            } else if nodeType == C.em_network_node_data_type_obj {
                s = append(s, fmt.Sprintf("%s", C.GoString(&branch.key[0])))
            }
        }
    } else if nodeType == C.em_network_node_data_type_array_obj ||
                nodeType == C.em_network_node_data_type_array_str ||
                nodeType == C.em_network_node_data_type_array_num {
        for i := 0; i < int(tree.num_children); i++ {
            branch = tree.child[i]
            s = append(s, fmt.Sprintf("%s[%d]", C.GoString(&tree.key[0]), i))
        }
    } else if nodeType == C.em_network_node_data_type_string {
        branch = tree.child[0]
        s = append(s, fmt.Sprintf("%s: %s", C.GoString(&branch.key[0]), C.GoString(&branch.value_str[0])))
    } else if nodeType == C.em_network_node_data_type_number {
        branch = tree.child[0]
        s = append(s, fmt.Sprintf("%s: %d", C.GoString(&branch.key[0]), int(branch.value_int)))
    } else if nodeType == C.em_network_node_data_type_false {
        branch = tree.child[0]
        s = append(s, fmt.Sprintf("%s: false", C.GoString(&branch.key[0])))
    } else if nodeType == C.em_network_node_data_type_true {
        branch = tree.child[0]
        s = append(s, fmt.Sprintf("%s: true", C.GoString(&branch.key[0])))
    } else {
        s = append(s, "")
    }

    return s

}

func (b *BaseTab) branch(id widget.TreeNodeID) bool {
    var tree     *C.em_network_node_t

    if id == "" {
        return true
    } else if strings.Contains(id, "[") && strings.Contains(id, "]") {
        return true
    } else if strings.Contains(id, ":") {
        return false
    }

    tree = b.getData()
    if tree == nil {
        log.Printf("Case 1: branch for id: %s false", id);
        return false
    }

    tree = C.get_network_tree_by_key(tree, C.CString(id))
    if tree == nil {
        log.Printf("Case 2: branch for id: %s false", id);
        return false
    }

    if int(tree.num_children) == 0 {
        return false
    }

    return true
}

func (b *BaseTab) create(branch bool) fyne.CanvasObject {
    return widget.NewLabel("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

func (b *BaseTab) update(id widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
    o.(*widget.Label).SetText(id)
}

func (b *BaseTab) getData() *C.em_network_node_t {
    return b.netNode
}

func (b *BaseTab) setData(data *C.em_network_node_t) {
    b.netNode = data
}

func (b *BaseTab) getCanvasObject() fyne.CanvasObject {
    return b.obj
}

func (b *BaseTab) setCanvasObject(obj fyne.CanvasObject) {
    b.obj = obj
}


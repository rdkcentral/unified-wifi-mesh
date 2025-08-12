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
//    "fyne.io/fyne/v2"
//    "fyne.io/fyne/v2/widget"
)

func (p *Policy) periodicTimer() {
    p.obj.Refresh()
}

/*
func (p *Policy) children(id widget.TreeNodeID) []widget.TreeNodeID {
	return p.children(id)
}

func (p *Policy) branch(id widget.TreeNodeID) bool {
	return p.branch(id)
}

func (p *Policy) create(branch bool) fyne.CanvasObject {
	return p.create(branch)
}

func (p *Policy) update(id widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
	p.update(id, branch, o)
}


func (p *Policy) getTreeData() *C.em_network_node_t {
	return p.getTreeData()
}

func (p *Policy) setTreeData(data *C.em_network_node_t) {
	p.setTreeData(data)
}
*/

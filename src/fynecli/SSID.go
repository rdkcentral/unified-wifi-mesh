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
//	"fyne.io/fyne/v2"
//    "fyne.io/fyne/v2/widget"
)

func (s *SSID) periodicTimer() {
	s.obj.Refresh()
}

/*
func (s *SSID) children(id widget.TreeNodeID) []widget.TreeNodeID {
	return s.children(id)
}

func (s *SSID) branch(id widget.TreeNodeID) bool {
	return s.branch(id)
}

func (s *SSID) create(branch bool) fyne.CanvasObject {
	return s.create(branch)
}

func (s *SSID) update(id widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
	s.update(id, branch, o)
}


func (s *SSID) getTreeData() *C.em_network_node_t {
	return s.getTreeData()
}

func (s *SSID) setTreeData(data *C.em_network_node_t) {
	s.setTreeData(data)
}
*/

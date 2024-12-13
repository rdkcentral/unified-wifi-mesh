package main

/*
#cgo CFLAGS: -I../../inc -I../../../OneWifi/include -I../../../OneWifi/source/utils -I../../../halinterface/include
#cgo LDFLAGS: -L../../install/lib -lemcli -lcjson -lreadline
#include <readline/readline.h>
#include <readline/history.h>
#include "em_cli_apis.h"

extern int editor_func(char *s);

static int register_editor_cb() {
	return init(editor_func);	
}
*/
import "C"

import (
	"unsafe"
	"fmt"
)

//export editor_func
func editor_func(*C.char) C.int {
	fmt.Println("Inside Go Callnack")
	return 0
}

func main() {

	C.register_editor_cb()
	for {
		prompt := C.CString("<<OneWifiMeshCli>>: ")
		line := C.readline(prompt)
		C.free(unsafe.Pointer(prompt))

		node := C.exec(line, C.strlen(line))
		if node != nil {
			C.print_network_tree(node)
			//C.network_tree_to_json(node)
			C.free_network_tree(node)
		}	

		C.free(unsafe.Pointer(line))
	}
	
}

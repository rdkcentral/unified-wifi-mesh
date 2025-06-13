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
//    "log"
    "errors"
    "strings"
    "strconv"
	"fyne.io/fyne/v2"
    "fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/dialog"
)

func portValidator(port string) error {

    num, err := strconv.Atoi(port)
    if err != nil {
        return errors.New("Invalid")
    } else if num > 65535 || num < 49152{
        return errors.New("Invalid")
    }

    return nil
}

func ipValidator(addr string) error {
    s := strings.Split(addr, ".")
    if (len(s) != 4) {
        return errors.New("Invalid")
    }

    for i:= 0; i < len(s); i++ {
        num, err := strconv.Atoi(s[i])
        if err != nil {
            return errors.New("Invalid")
        } else if num > 255 {
            return errors.New("Invalid")
        }
    }

    return nil
}


func settingsAction() {
	remoteAddr := widget.NewEntry()
    remoteAddr.SetPlaceHolder("10.0.0.140")
    remoteAddr.Validator = ipValidator
    remotePort := widget.NewEntry()
    remotePort.SetPlaceHolder("49153")
    remotePort.Validator = portValidator
    d := dialog.NewForm(
    		"Controller Address",
            "OK",
            "Cancel",
            []*widget.FormItem{
            	{Text: "IPv4", Widget: remoteAddr},
            	{Text: "Port", Widget: remotePort},
            },
            func (valid bool) {
            	var ip int
                var num int

                if valid == false {
                	return
                }


                s := strings.Split(remoteAddr.Text, ".");
                for i:= 0; i < len(s); i++ {
                	num, _ := strconv.Atoi(s[i])
                    ip |= num << (8 * i)
                }

                num, _ = strconv.Atoi(remotePort.Text)

                C.set_remote_addr(C.uint(ip), C.uint(num), C.bool(true))
            },
            meshViewsMgr.meshWindow,
    )
    d.Resize(fyne.NewSize(450, 100))
    d.Show()
}


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
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const remoteCtrl_Addr_path = "/nvram/remoteCtrl.json"

type RemoteIPConfig struct {
    IP   string `json:"ip"`
    Port string `json:"port"`
}

func portValidator(port string) error {

    num, err := strconv.Atoi(port)
    if err != nil {
        return errors.New("Invalid")
    } else if num > 65535 || num < 49152 {
        return errors.New("Invalid")
    }

    return nil
}

func ipValidator(addr string) error {
    s := strings.Split(addr, ".")
    if len(s) != 4 {
        return errors.New("Invalid IP format")
    }

    for i := 0; i < len(s); i++ {
        num, err := strconv.Atoi(s[i])
        if err != nil || num < 0 || num > 255 {
            return errors.New("Invalid  IP format")
        }
    }

    return nil
}

func settingsAction() {
    var remoteIPcfg RemoteIPConfig
    data, err := os.ReadFile(remoteCtrl_Addr_path)
    if err == nil {
        _ = json.Unmarshal(data, &remoteIPcfg)
    } else {
        // fallback if file doesn't exist
        remoteIPcfg = RemoteIPConfig{IP: "", Port: ""}
    }
    remoteAddr := widget.NewEntry()
    remoteAddr.SetPlaceHolder("10.0.0.140")
    remoteAddr.Validator = ipValidator
    remoteAddr.SetText(remoteIPcfg.IP)

    remotePort := widget.NewEntry()
    remotePort.SetPlaceHolder("49153")
    remotePort.Validator = portValidator
    remotePort.SetText(remoteIPcfg.Port)

    d := dialog.NewForm(
        "Controller Address",
        "OK",
        "Cancel",
        []*widget.FormItem{
            {Text: "IPv4", Widget: remoteAddr},
            {Text: "Port", Widget: remotePort},
        },
        func(valid bool) {
            var ip int
            var num int

            if valid == false {
                return
            }

            // Get updated values
            remoteIPcfg.IP = remoteAddr.Text
            remoteIPcfg.Port = remotePort.Text

            s := strings.Split(remoteAddr.Text, ".")
            for i := 0; i < len(s); i++ {
                num, _ := strconv.Atoi(s[i])
                ip |= num << (8 * i)
            }

            num, _ = strconv.Atoi(remotePort.Text)

            // Save to config file
            newData, _ := json.MarshalIndent(remoteIPcfg, "", "  ")
            _ = os.WriteFile(remoteCtrl_Addr_path, newData, 0644)

            C.set_remote_addr(C.uint(ip), C.uint(num), C.bool(true))
        },
        meshViewsMgr.meshWindow,
    )
    d.Resize(fyne.NewSize(450, 100))
    d.Show()
}

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

	"log"
	"net/url"

	"fyne.io/fyne/v2"
)

var (
    wifiResetItem *fyne.MenuItem
    networkName *fyne.MenuItem
)

func InitMenuItems() {
    wifiResetItem = fyne.NewMenuItem("Reset", nil)
    networkName = fyne.NewMenuItem("Network Name", nil)

    // Initially disabled
    wifiResetItem.Disabled = true
    networkName.Disabled = true
}

func enableMenuItems(m *MeshViewsMgr) {
    // enable the menu options
    wifiResetItem.Disabled = false
    networkName.Disabled = false

    // Trigger menu redraw
    fyne.Do(func() {
        m.meshWindow.SetMainMenu(BuildMainMenu(m))
    })

}

func BuildMainMenu(meshViewsMgr *MeshViewsMgr) *fyne.MainMenu {

    wifiResetItem.Action = func() {
        ShowWifiResetDialog(meshViewsMgr)
    }

    connectItem := fyne.NewMenuItem("Connection", func() {
        log.Println("Connecting to remote...")
        settingsAction()
    })

    networkName.Action = func() {
        ShowNetworkNameDialog(meshViewsMgr)
    }


    helpItem := fyne.NewMenuItem("Help", func() {
        u, err := url.Parse("https://wiki.rdkcentral.com/display/RDK/unified-wifi-mesh+on+RDK-B")
        if err == nil {
            _ = fyne.CurrentApp().OpenURL(u)
        }
    })

    return fyne.NewMainMenu(
        fyne.NewMenu("Settings",
            connectItem,
            networkName,
            wifiResetItem,
        ),
        fyne.NewMenu("Help", helpItem),
    )
}

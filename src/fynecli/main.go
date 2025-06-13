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
	"log"
	"time"
    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/widget"
)

const (
    linesToDisplay int = 38

    TopologyString    = "Topology"
    SSIDString    = "SSID List"
    RadioString          = "WiFi Radios"
    ChannelString       = "WiFi Channels"
    MLDString = "Multi Link Operations"
    ClientString      = "Client Connections"
    PolicyString      = "Policy"
    NeighborString      = "WiFi Neighbors"
    SteerDevicesString       = "Optimize Client Connections"
    BackhaulOptimizeString   = "Optimize Backhaul Connections"
    NetworkMetricsString     = "Network Metrics"
    DeviceOnboardingString   = "Onboarding & Provisioning"
    WiFiEventsString         = "WiFi Events"
    WiFiResetString          = "WiFi Reset"
    DebugString              = "Debugging & Testing"

    GET  = 0
    GETX = 1
    SET  = 2

    BTN_UPDATE = 0
    BTN_APPLY  = 1
    BTN_CANCEL = 2
    BTN_MAX    = 3
)

type BaseTab struct {
	netNode		*C.em_network_node_t
	obj		fyne.CanvasObject
}

type SSID struct {
	BaseTab
}

type Policy struct {
	BaseTab
}

type Topology struct {
	BaseTab
	topo	*fyne.Container
}

type TabInterface interface {
	children(widget.TreeNodeID) []widget.TreeNodeID
	branch(widget.TreeNodeID) bool
	create(bool) fyne.CanvasObject
	update(widget.TreeNodeID, bool, fyne.CanvasObject)
	getData() *C.em_network_node_t
	setData(*C.em_network_node_t)
	getCanvasObject() fyne.CanvasObject
	setCanvasObject(fyne.CanvasObject)
	periodicTimer()
}

type EasyMeshView struct {
    title                string   
    get           string
    getEx         string
    set           string
    help                 string
    allowUnmod	bool
	tabInterface	TabInterface
	tabItem		*container.TabItem
}

type MeshViewsMgr struct {
	meshApp			fyne.App
	meshWindow 		fyne.Window
	toolBar			*widget.Toolbar
	appTabs			*container.AppTabs
    ticker              *time.Ticker
    quit        chan bool
	easyMeshViews             map[string]EasyMeshView
}

var meshViewsMgr MeshViewsMgr

func (m *MeshViewsMgr) createViews() {
	var tabInterface TabInterface

	m.easyMeshViews = make(map[string]EasyMeshView)

	topo := Topology{}
	tabInterface = &topo
	image := canvas.NewImageFromResource(resourceGatewayPng)
	image.Resize(fyne.Size{Width: 50, Height: 50})
	tabInterface.setCanvasObject(image)
	topo.topo = container.New(&Concentric{}, tabInterface.getCanvasObject())

    m.easyMeshViews[TopologyString] = EasyMeshView{
            title:                TopologyString,
            get:           "get_bss OneWifiMesh",
            getEx:         "",
            set:           "",
            help:                 "",
            allowUnmod: false,
            //tabItem: container.NewTabItemWithIcon("", theme.HomeIcon(), tabInterface.getCanvasObject()),
            tabItem: container.NewTabItemWithIcon("", theme.HomeIcon(), topo.topo),
			tabInterface: tabInterface,
        }

	tabInterface = &Policy{}
	tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
	m.easyMeshViews[PolicyString] = EasyMeshView{
            title:                PolicyString,
            get:           "get_policy OneWifiMesh",
            getEx:         "get_policy OneWifiMesh",
            set:           "set_policy OneWifiMesh",
            help:                 "",
            allowUnmod: false,
            tabItem: container.NewTabItemWithIcon("", resourcePolicyPng, tabInterface.getCanvasObject()),
			tabInterface: tabInterface,
		}	

	tabInterface = &SSID{}
	tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
	m.easyMeshViews[SSIDString] = EasyMeshView{
            title:                SSIDString,
            get:           "get_ssid OneWifiMesh",
            getEx:         "get_ssid OneWifiMesh",
            set:           "set_ssid OneWifiMesh",
            help:                 "",
            allowUnmod: false,
            tabItem: container.NewTabItemWithIcon("", resourceSsidPng, tabInterface.getCanvasObject()),
			tabInterface: tabInterface,
        }

}

func (m *MeshViewsMgr) getViewBySelectedTab() *EasyMeshView {
    for _, value := range m.easyMeshViews {
        if m.appTabs.Selected() == value.tabItem {
            return &value
        }
    }
    return nil
}

func (m *MeshViewsMgr) timerHandler() {
	for {
		select {
        	case <-m.ticker.C:
				if C.is_remote_addr_valid() == true {
					view := m.getViewBySelectedTab()
					if view != nil {
       					//view.tabInterface.setData(C.exec(C.CString(view.get), C.strlen(C.CString(view.get)), nil)) 
						//dumpNetNode(view.tabInterface.getData())
						view.tabInterface.periodicTimer()
					} else {
						log.Printf("No matching AppTab")
					}
    			}
  
        	case <-m.quit:
            	m.ticker.Stop()
            	return
		}
	}
}

func main() {
    meshViewsMgr.meshApp = app.New()
    meshViewsMgr.meshWindow = meshViewsMgr.meshApp.NewWindow("OneWifiMesh")

	meshViewsMgr.createViews()

	meshViewsMgr.toolBar = widget.NewToolbar(
        widget.NewToolbarAction(theme.SettingsIcon(), settingsAction),
        widget.NewToolbarSeparator(),
        widget.NewToolbarAction(theme.ContentAddIcon(), func() {}),
        widget.NewToolbarAction(theme.ContentUndoIcon(), func() {}),
        widget.NewToolbarAction(theme.ComputerIcon(), func() {}),
        widget.NewToolbarAction(theme.HistoryIcon(), func() {}),
        widget.NewToolbarSpacer(),
        widget.NewToolbarAction(theme.HelpIcon(), func() {
            log.Printf("Display help")
        }),
    )

	meshViewsMgr.appTabs = container.NewAppTabs(
		meshViewsMgr.easyMeshViews[TopologyString].tabItem,
		meshViewsMgr.easyMeshViews[PolicyString].tabItem,
		meshViewsMgr.easyMeshViews[SSIDString].tabItem,
    )

    meshViewsMgr.appTabs.SetTabLocation(container.TabLocationLeading)
	meshViewsMgr.meshWindow.SetContent(container.NewBorder(meshViewsMgr.toolBar, nil, meshViewsMgr.appTabs, nil, nil))

	meshViewsMgr.ticker = time.NewTicker(1 * time.Second)
    go meshViewsMgr.timerHandler()
	meshViewsMgr.quit = make(chan bool)

    meshViewsMgr.meshWindow.Resize(fyne.NewSize(800, 600))
    meshViewsMgr.meshWindow.ShowAndRun()

	meshViewsMgr.quit <- true
}


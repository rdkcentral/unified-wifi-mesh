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

	//"fyne.io/fyne/layout"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
    linesToDisplay int = 38

    TopologyString         = "Topology"
    SSIDString             = "SSID List"
    RadioString            = "WiFi Radios"
    ChannelString          = "WiFi Channels"
    MLDString              = "Multi Link Operations"
    ClientString           = "Client Connections"
    PolicyString           = "Policy"
    NeighborString         = "WiFi Neighbors"
    SteerDevicesString     = "Optimize Client Connections"
    BackhaulOptimizeString = "Optimize Backhaul Connections"
    NetworkMetricsString   = "Network Metrics"
    DeviceOnboardingString = "Onboarding & Provisioning"
    WiFiEventsString       = "WiFi Events"
    WiFiResetString        = "WiFi Reset"
    DebugString            = "Debugging & Testing"

    GET  = 0
    GETX = 1
    SET  = 2

    BTN_UPDATE = 0
    BTN_APPLY  = 1
    BTN_CANCEL = 2
    BTN_MAX    = 3
)

type BaseTab struct {
    netNode *C.em_network_node_t
    obj     fyne.CanvasObject
}

type Topology struct {
    BaseTab
    topo *fyne.Container
}

type Policy struct {
    BaseTab
}

type SSID struct {
    BaseTab
}

type WifiRadio struct {
    BaseTab
}

type WifiChannel struct {
    BaseTab
}

type ClientDevice struct {
    BaseTab
}

type WifiNeighbors struct {
    BaseTab
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
    title        string
    get          string
    getEx        string
    set          string
    help         string
    allowUnmod   bool
    tabInterface TabInterface
    tabItem      *container.TabItem
}

type MeshViewsMgr struct {
    meshApp              fyne.App
    meshWindow           fyne.Window
    toolBar              *widget.Toolbar
    appTabs              *container.AppTabs
    ticker               *time.Ticker
    quit                 chan bool
    isEditing            bool
    menuItemsEnabled     bool
    activeTabWhenEditing *container.TabItem
    easyMeshViews        map[string]EasyMeshView
    originalTabContent   map[*container.TabItem]fyne.CanvasObject
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
        title: TopologyString,
        get:   "get_bss OneWifiMesh",
        //tabItem: container.NewTabItemWithIcon("", theme.HomeIcon(), tabInterface.getCanvasObject()),
        tabItem:      container.NewTabItemWithIcon("", theme.HomeIcon(), topo.topo),
        tabInterface: tabInterface,
    }

    tabInterface = &Policy{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[PolicyString] = EasyMeshView{
        title:        PolicyString,
        get:          "get_policy OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourcePolicyPng, tabInterface.getCanvasObject()),
        tabInterface: tabInterface,
    }

    tabInterface = &SSID{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[SSIDString] = EasyMeshView{
        title:        SSIDString,
        get:          "get_ssid OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourceSsidPng, tabInterface.getCanvasObject()),
        tabInterface: tabInterface,
    }

    tabInterface = &WifiRadio{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[RadioString] = EasyMeshView{
        title:        RadioString,
        get:          "get_radio OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourceWifiradioPng, tabInterface.getCanvasObject()),
        tabInterface: tabInterface,
    }

    tabInterface = &WifiChannel{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[ChannelString] = EasyMeshView{
        title:        ChannelString,
        get:          "get_channel OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourceWifiChannelPng, tabInterface.getCanvasObject()),
        tabInterface: tabInterface,
    }

    tabInterface = &WifiNeighbors{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[NeighborString] = EasyMeshView{
        title:        NeighborString,
        get:          "scan_result OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourceWifiNeighborsPng, tabInterface.getCanvasObject()),
        tabInterface: tabInterface,
    }

    tabInterface = &ClientDevice{}
    tabInterface.setCanvasObject(widget.NewTree(tabInterface.children, tabInterface.branch, tabInterface.create, tabInterface.update))
    m.easyMeshViews[ClientString] = EasyMeshView{
        title:        ClientString,
        get:          "get_sta OneWifiMesh",
        tabItem:      container.NewTabItemWithIcon("", resourceDeviceConnectionPng, tabInterface.getCanvasObject()),
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

            if m.isEditing {
                //Skip updates while in edit mode
                continue
            }

            if C.is_remote_addr_valid() == true {
                if !m.menuItemsEnabled {
                    enableMenuItems(m)
                    m.menuItemsEnabled = true
                }
                view := m.getViewBySelectedTab()
                if view != nil {
                    fyne.Do(func() {
                        view.tabInterface.setData(C.exec(C.CString(view.get), C.strlen(C.CString(view.get)), nil))
                        //dumpNetNode(view.tabInterface.getData())
                        view.tabInterface.periodicTimer()
                    })
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

    InitMenuItems()
    meshViewsMgr.meshWindow.SetMainMenu(BuildMainMenu(&meshViewsMgr))

    meshViewsMgr.appTabs = container.NewAppTabs(
        meshViewsMgr.easyMeshViews[TopologyString].tabItem,
        meshViewsMgr.easyMeshViews[PolicyString].tabItem,
        meshViewsMgr.easyMeshViews[SSIDString].tabItem,
        meshViewsMgr.easyMeshViews[RadioString].tabItem,
        meshViewsMgr.easyMeshViews[ChannelString].tabItem,
        meshViewsMgr.easyMeshViews[NeighborString].tabItem,
        meshViewsMgr.easyMeshViews[ClientString].tabItem,
    )

    meshViewsMgr.appTabs.OnSelected = func(tab *container.TabItem) {
        if meshViewsMgr.isEditing && tab != meshViewsMgr.activeTabWhenEditing {
            // Revert back to the editing tab
            current := meshViewsMgr.activeTabWhenEditing
            go func() {
                time.Sleep(50 * time.Millisecond) // wait for the UI
                fyne.Do(func() {
                    for i, t := range meshViewsMgr.appTabs.Items {
                        if t == current {
                            meshViewsMgr.appTabs.SelectIndex(i)
                            break
                        }
                    }
                })
            }()
        }
    }

    meshViewsMgr.appTabs.SetTabLocation(container.TabLocationLeading)
    //meshViewsMgr.meshWindow.SetContent(container.NewBorder(meshViewsMgr.toolBar, nil, meshViewsMgr.appTabs, nil, nil))
    meshViewsMgr.meshWindow.SetContent(meshViewsMgr.appTabs)

    meshViewsMgr.ticker = time.NewTicker(5 * time.Second)
    go meshViewsMgr.timerHandler()
    meshViewsMgr.quit = make(chan bool)

    meshViewsMgr.meshWindow.Resize(fyne.NewSize(800, 600))
    meshViewsMgr.meshWindow.ShowAndRun()

    meshViewsMgr.quit <- true
}

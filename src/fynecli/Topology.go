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
	"encoding/json"
	"fmt"
	"image/color"
	"log"
	"math"
	"math/rand"

	"os"
	"sort"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/lucasb-eyer/go-colorful"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
	"gonum.org/v1/gonum/spatial/r2"
)

type Concentric struct {
}

type Root struct {
	Status string `json:"Status"`
	Result Result `json:"Result"`
}

type Result struct {
	Device Device `json:"Device"`
}

type Device struct {
	ID        string    `json:"ID"`
	Backhaul  *Backhaul `json:"Backhaul,omitempty"`
	RadioList []Radio   `json:"RadioList,omitempty"`
}

type Backhaul struct {
	MACAddress string   `json:"MACAddress"`
	MediaType  string   `json:"MediaType"`
	Child      []Device `json:"Child,omitempty"`
}

type DeviceWrapper struct {
	Device Device `json:"Device"`
}

type Radio struct {
	ID                 string `json:"ID"`
	Enabled            bool   `json:"Enabled"`
	Band               int    `json:"Band"`
	IEEE               string `json:"IEEE"`
	Channel            int    `json:"CHannel"`
	BSSList            []BSS  `json:"BSSList"`
}

type BSS struct {
	BSSID     string `json:"BSSID"`
	MLDAddr   string `json:"MLDAddr"`
	HaulType  string `json:"HaulType"`
	VlanId    int    `json:"VlanId"`
	SSID      string `json:"SSID"`
	VapMode   int    `json:"VapMode"`
	Band      int    `json:"Band"`
	IEEE      string `json:"IEEE"`
	STAList   []STA  `json:"STAList"`
}

type STA struct {
	MACAddress     string `json:"MACAddress"`
	MLDAddr        string `json:"MLDAddr"`
	ClientType     string `json:"ClientType"`
	Associated     bool   `json:"Associated"`
	SignalStrength int    `json:"SignalStrength"`
	SupportedRates string `json:"SupportedRates"`
}

type Band struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

type HaulTypeVisual struct {
	Name        string     `json:"name"`
	SSID        string     `json:"ssid"`
	VlanId      int        `json:"VlanId"`
	Color       color.RGBA `json:"color"`
	Radius      float32    `json:"radius"`
	OffsetIndex int        `json:"offsetIndex"` // new field
	BSSList     []BSS      `json:"BSSList"`
}

type RawNode struct {
	Name       string           `json:"name"`
	X          float32          `json:"x"`
	Y          float32          `json:"y"`
	SymbolSize float32          `json:"symbolSize"`
	Bands      []Band           `json:"bands"`
	RadioList  []Radio          `json:"RadioList"`
	HaulTypes  []HaulTypeVisual `json:"haulTypes"`
	Icon       fyne.Resource    `json:"-"`
	STAList    []STAWithContext `json:"staList"`
}

type BandEdge struct {
	From     string
	To       string
	Band     int
	HaulType string
	Channel  int
}

type STAWithContext struct {
	STA      STA
	Band     int
	HaulType string
	SSID     string
	Icon     fyne.Resource `json:"-"`
	X        float32       `json:"x"`
	Y        float32       `json:"y"`
}

type RawLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Band   int    `json:"band"`
}

type TopologyData struct {
	Nodes []RawNode `json:"nodes"`
	Links []RawLink `json:"links"`
}

type BandCircleButton struct {
	widget.BaseWidget
	color     color.Color
	radius    float32
	onTapped  func()
	highlight bool
}

type bandCircleRenderer struct {
	circle  *canvas.Circle
	border  *canvas.Circle
	button  *BandCircleButton
	objects []fyne.CanvasObject
}

type TopologyNode struct {
	Status string `json:"Status"`
	Result struct {
		Device Device `json:"Device"`
	} `json:"Result"`
}

type ClickableImage struct {
    widget.BaseWidget
    image    *canvas.Image
    onTapped func()
}

// Map to keep track of node IDs
var nodeMap = map[string]graph.Node{}
var g = simple.NewDirectedGraph()

var tooltipText *canvas.Text

var currentTooltipBg fyne.CanvasObject
var currentTooltipText fyne.CanvasObject
var currentTooltipCloseBtn fyne.CanvasObject
var tooltipTimer *time.Timer

var triangleOffsets = []struct{ X, Y float32 }{
	{X: -75, Y: 50},
	{X: 75, Y: 50},
	{X: 0, Y: -75},
}

func NewClickableImage(res fyne.Resource, onTapped func()) *ClickableImage {
    img := canvas.NewImageFromResource(res)
    img.FillMode = canvas.ImageFillContain
    img.SetMinSize(fyne.NewSize(40, 40)) // Set desired size

    c := &ClickableImage{
        image:    img,
        onTapped: onTapped,
    }
    c.ExtendBaseWidget(c)
    return c
}

func (c *ClickableImage) CreateRenderer() fyne.WidgetRenderer {
    return widget.NewSimpleRenderer(c.image)
}

func (c *ClickableImage) Tapped(_ *fyne.PointEvent) {
	c.Refresh()
    if c.onTapped != nil {
        c.onTapped()
    }
}

func (c *ClickableImage) Destroy() {}

func getTestJSONFile(timerCount int) string {
    files := []string{
        "../../src/fynecli/example/network_topo.json",
        "../../src/fynecli/example/network_topo1.json",
        "../../src/fynecli/example/network_topo2.json",
        "../../src/fynecli/example/network_topo3.json",
    }
    index := (timerCount) / 4 % len(files)
    return files[index]
}

func getIconForClientType(clientType string) fyne.Resource {
    lower := strings.ToLower(clientType)

    switch {
    case strings.Contains(lower, "iphone"):
        return resourceIphonePng
    case strings.Contains(lower, "ipad"):
        return resourceIpadPng
    case strings.Contains(lower, "android"):
        return resourceAndroidPng
    case strings.Contains(lower, "laptop"):
        return resourceLaptopPng
    default:
        return  resourceAndroidPng// fallback icon
    }

}

/* func: loadNestedTopologyFromDeviceTree()
 * Description:
 * This function parse the network topology tree 
* and set the respective stricture to draw the graph
 * returns: N/A
 */
func loadNestedTopologyFromDeviceTree(tree *C.em_network_node_t, container *fyne.Container) (*simple.UndirectedGraph, map[string]graph.Node, map[string]RawNode, []BandEdge, error) {
    // local variables
	const (
        r         = 300.0
        staRadius = 80.0
        rootSize  = 70
        childSize = 50
        angleStep = 50.0
    )

    g := simple.NewUndirectedGraph()
    nodeMap := make(map[string]graph.Node)
    metaMap := make(map[string]RawNode)
    var bandEdges []BandEdge

    canvasSize := container.Size()
    canvasWidth := canvasSize.Width

    var rootDeviceNode *C.em_network_node_t
    var rootDeviceID string

	// Parse for root device
	backhaulTree := C.get_network_tree_by_key(tree, C.CString("Backhaul"))
    if backhaulTree == nil {
        return g, nodeMap, metaMap, bandEdges, nil
    }

	// Parse for collocated agent
	childNode := C.get_network_tree_by_key(backhaulTree, C.CString("Child"))
    if childNode == nil {
        return g, nodeMap, metaMap, bandEdges, nil
    }

    // Prase the tree and get the root node
    if int(childNode.num_children) > 0 {
        child := childNode.child[int(childNode.num_children)-1]
        childBackhaulTree := C.get_network_tree_by_key(child, C.CString("Backhaul"))
        if getTreeValue(childBackhaulTree, "MACAddress") == "00:00:00:00:00:00" {
            rootDeviceNode = child
            rootDeviceID = getTreeValue(child, "ID")
        }
    }

    if rootDeviceNode == nil {
        return nil, nil, nil, nil, fmt.Errorf("root device not found")
    }

    // Helper function for createSTAList
    createSTAList := func(deviceX, deviceY float32, radioNode *C.em_network_node_t) []STAWithContext {
        var staList []STAWithContext
        for i := 0; i < int(radioNode.num_children); i++ {
            radio := radioNode.child[i]
            bssNode := C.get_network_tree_by_key(radio, C.CString("BSSList"))
            for j := 0; j < int(bssNode.num_children); j++ {
                bss := bssNode.child[j]
                staNode := C.get_network_tree_by_key(bss, C.CString("STAList"))
                for k := 0; k < int(staNode.num_children); k++ {
                    sta := staNode.child[k]

                    if getTreeValue(sta, "Associated") == "false" || getTreeValue(sta, "SSID") == "" {
                        continue
                    }

                    staSSID := getTreeValue(sta, "SSID")
                    bssHaulType := getTreeValue(bss, "HaulType")
                    if bssHaulType == "Backhaul" && getTreeValue(bss, "SSID") == staSSID {
                        continue
                    }

                    theta := -60.0 * (math.Pi / 180)
                    staX := deviceX + float32(staRadius)*float32(math.Cos(theta))
                    staY := deviceY + float32(staRadius)*float32(math.Sin(theta))
                    staList = append(staList, STAWithContext{
                        STA:      parseSTA(sta),
                        Band:     getKeyIntValue(radio, "Band"),
                        HaulType: getTreeValue(bss, "HaulType"),
                        SSID:     getTreeValue(bss, "SSID"),
                        Icon:     getIconForClientType(getTreeValue(sta, "ClientType")),
                        X:        staX,
                        Y:        staY,
                    })
                    theta -= 50
                }
            }
        }
        return staList
    }

    // Helper function for createNode
    createNode := func(deviceNode *C.em_network_node_t, x, y float32, size float32) string {
        deviceID := getTreeValue(deviceNode, "ID")
        node := g.NewNode()
        g.AddNode(node)
        nodeMap[deviceID] = node

        icon := resourceExtenderPng
        if deviceID == rootDeviceID {
            icon = resourceGatewayPng
        }

        radios := parseRadioList(deviceNode.child[2])

        metaMap[deviceID] = RawNode{
            Name:       deviceID,
            X:          x,
            Y:          y,
            SymbolSize: size,
            RadioList:  radios,
            Bands:      getBandsFromRadioList(radios),
            HaulTypes:  buildHaulTypes(radios),
            Icon:       icon,
            STAList:    createSTAList(x, y, deviceNode.child[2]),
        }
        return deviceID
    }

    // Recursive traversal
    var traverse func(deviceNode *C.em_network_node_t, parentX, parentY float32, baseAngle float64, depth int)
    traverse = func(deviceNode *C.em_network_node_t, parentX, parentY float32, baseAngle float64, depth int) {
        if deviceNode == nil {
            return
        }

        deviceID := getTreeValue(deviceNode, "ID")
        if _, exists := nodeMap[deviceID]; !exists {
            var x, y float32
            var size float32

            if deviceID == rootDeviceID {
                x = -canvasWidth/2 + 190
                y = 0
                size = rootSize
            } else {
                theta := baseAngle * (math.Pi / 180)
                x = parentX + float32(r)*float32(math.Cos(theta))
                y = parentY + float32(r)*float32(math.Sin(theta))
                size = childSize
            }

            createNode(deviceNode, x, y, size)
        }

        backhaul := C.get_network_tree_by_key(deviceNode, C.CString("Backhaul"))
        if backhaul == nil {
            return
        }

        childList := C.get_network_tree_by_key(backhaul, C.CString("Child"))
        if childList == nil {
            return
        }

        for i := 0; i < int(childList.num_children); i++ {
            child := childList.child[i]
            childID := getTreeValue(child, "ID")

            childAngle := baseAngle + float64(i)*angleStep

            if _, exists := nodeMap[childID]; !exists {
                theta := childAngle * (math.Pi / 180)
                childX := metaMap[deviceID].X + float32(r)*float32(math.Cos(theta))
                childY := metaMap[deviceID].Y + float32(r)*float32(math.Sin(theta))
				if depth == 0 {
				    if(i==0) {
					    childY -= 130
					    childX -= 50
				    } else if(i==1) {
					    childY -= 80
					    childX += 60
				    }
			    } else if depth == 1 {
					if(i==0) {
					    childY += 130
					    childX -= 50
				    }
				} 

                createNode(child, childX, childY, childSize)
            }

            // parse the band with extender connected
            band, channel := getBandAndChannelFromRadioTree(child.child[2])

            g.SetEdge(g.NewEdge(nodeMap[deviceID], nodeMap[childID]))
            bandEdges = append(bandEdges, BandEdge{
                From:     deviceID,
                To:       childID,
                Band:     band,
                Channel:  channel,
            })

            traverse(child, metaMap[deviceID].X, metaMap[deviceID].Y, childAngle, depth+1)
        }
    }

    traverse(rootDeviceNode, 0, 0, 0, 0)
    return g, nodeMap, metaMap, bandEdges, nil
}

/* func: loadNestedTopologyJSON()
 * Description:
 * This function parse the network topology static json files 
 * and set the respective stricture to draw the graph
 * returns: N/A
 */
func loadNestedTopologyJSON(path string, container *fyne.Container) (*simple.UndirectedGraph, map[string]graph.Node, map[string]RawNode, []BandEdge, error) {
	// open the json file
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer file.Close()

	var topo TopologyNode
	if err := json.NewDecoder(file).Decode(&topo); err != nil {
		return nil, nil, nil, nil, err
	}

	const (
		r         = 300.0
		staRadius = 80.0
		rootSize  = 70
		childSize = 50
		angleStep = 50.0
	)

	g := simple.NewUndirectedGraph()
	nodeMap := make(map[string]graph.Node)
	metaMap := make(map[string]RawNode)
	var bandEdges []BandEdge

	var rootDeviceID string

	// Helper function for createSTAList
	createSTAList := func(deviceX, deviceY float32, radioList []Radio) []STAWithContext {
		var staList []STAWithContext
		for _, radio := range radioList {
			for _, bss := range radio.BSSList {
				for _, sta := range bss.STAList {
					theta := -60.0 * (math.Pi / 180)
					staX := deviceX + float32(staRadius)*float32(math.Cos(theta))
					staY := deviceY + float32(staRadius)*float32(math.Sin(theta))
					staIcon := getIconForClientType(sta.ClientType)
					staList = append(staList, STAWithContext{
						STA:      sta,
						Band:     radio.Band,
						HaulType: bss.HaulType,
						SSID:     bss.SSID,
						Icon:     staIcon,
						X:        staX,
						Y:        staY,
					})
					theta = theta - 50
				}
			}
		}
		return staList
	}

	// Helper function for createNode
	createNode := func(device Device, x, y float32, size float32) {
		node := g.NewNode()
		g.AddNode(node)
		nodeMap[device.ID] = node

		icon := resourceExtenderPng
		if device.ID == rootDeviceID {
			icon = resourceGatewayPng
		}

		metaMap[device.ID] = RawNode{
			Name:       device.ID,
			X:          x,
			Y:          y,
			SymbolSize: size,
			RadioList:  device.RadioList,
			Bands:      getBandsFromRadioList(device.RadioList),
			HaulTypes:  buildHaulTypes(device.RadioList),
			Icon:       icon,
			STAList:    createSTAList(x, y, device.RadioList),
		}
	}

	canvasSize := container.Size()
	canvasWidth := canvasSize.Width

	// Recursive traversal
	var traverse func(device Device, parentX, parentY float32, baseAngle float64, depth int)
	traverse = func(device Device, parentX, parentY float32, baseAngle float64, depth int) {
		if device.ID == "" {
			return
		}

		if _, exists := nodeMap[device.ID]; !exists {
			var x, y float32
			var size float32

			if device.ID == rootDeviceID {
				//x, y, size = 0, 0, rootSize

				x = -canvasWidth/2 + 190
				y = 0
				size = rootSize

			} else {
				theta := baseAngle * (math.Pi / 180)
				x = parentX + float32(r)*float32(math.Cos(theta))
				y = parentY + float32(r)*float32(math.Sin(theta))
				size = childSize
			}

			createNode(device, x, y, size)
		}

		if device.Backhaul == nil {
			return
		}

		for i, child := range device.Backhaul.Child {
			if child.ID == "" {
				continue
			}

			childAngle := baseAngle + float64(i)*angleStep
			if _, exists := nodeMap[child.ID]; !exists {
				theta := childAngle * (math.Pi / 180)
				childX := metaMap[device.ID].X + float32(r)*float32(math.Cos(theta))
				childY := metaMap[device.ID].Y + float32(r)*float32(math.Sin(theta))

				//Apply depth-based offset
				log.Printf("Dept: %d, childId: %s\n", depth, child.ID)
				if depth == 0 {
					if child.ID == "ea:f6:db:3b:bb:71" {
						childY -= 130
						childX -= 50
				    }

					if child.ID == "e2:42:20:03:25:a6" {
						childY -= 80 // Move Extender 1 upward by 50 pixels
					    childX += 60
				    }

				} else if depth == 1 {
					if child.ID == "e2:42:20:03:25:a5" {
					    childY += 130 // Move Extender 1 upward by 50 pixels
					    childX -= 50
				    }
				}

				createNode(child, childX, childY, childSize)
			}

			band := -1
			channel := 36
			haulType := "unknown"
			for _, radio := range child.RadioList {
				for _, bss := range radio.BSSList {
					if bss.VapMode == 1 {
						band = radio.Band
						haulType = bss.HaulType
						channel = radio.Channel
						break
					}
				}
				if band != -1 {
					break
				}
			}

			fmt.Printf("Edge from %s to %s uses HaulType: %s (Band: %d), Channel\n", device.ID, child.ID, haulType, band, channel)
			g.SetEdge(g.NewEdge(nodeMap[device.ID], nodeMap[child.ID]))
			bandEdges = append(bandEdges, BandEdge{
				From:     device.ID,
				To:       child.ID,
				Band:     band,
				HaulType: haulType,
				Channel:  channel,
			})

			traverse(child, metaMap[device.ID].X, metaMap[device.ID].Y, childAngle, depth+1)
		}
	}

	var rootDevice *Device
	for _, child := range topo.Result.Device.Backhaul.Child {
		if child.Backhaul.MACAddress == "00:00:00:00:00:00" {
			rootDevice = &child
			rootDeviceID = child.ID
			break
		}
	}

	if rootDevice == nil {
		return nil, nil, nil, nil, fmt.Errorf("no device with MACAddress 00:00:00:00:00:00 found")
	}

	traverse(*rootDevice, 0, 0, 0, 0)
	return g, nodeMap, metaMap, bandEdges, nil
}

/* func: drawNetworkTopologyGraph()
 * Description:
 * This function draw the mesh network topology
 * returns: N/A
 */
func drawNetworkTopologyGraph(
	g *simple.UndirectedGraph,
	nodeMap map[string]graph.Node,
	metaMap map[string]RawNode,
	bandEdges []BandEdge,
	container *fyne.Container,
) {
	idToName := make(map[int64]string)

	// Get the convas Size
	canvasSize := container.Size()
	canvasOffset := fyne.NewPos(canvasSize.Width/2, canvasSize.Height/2)

	// Home  or Topology Page header
	heading := canvas.NewText("RDK Mesh Network", parseHexColor("#708090"))
	heading.TextStyle = fyne.TextStyle{Bold: true}
	heading.TextSize = 25
	heading.Move(fyne.NewPos(10, 10))
	container.Add(heading)

	for name, node := range nodeMap {
		idToName[node.ID()] = name
	}

	for _, node := range graph.NodesOf(g.Nodes()) {
		name := idToName[node.ID()]
		meta := metaMap[name]
		pos := fyne.NewPos(meta.X+canvasOffset.X, meta.Y+canvasOffset.Y)

		// Parse the haulType and create a partial overlapping haultype circle
		for _, ht := range meta.HaulTypes {
			// transparentColor for haul type
			transparentCol := color.RGBA{R: ht.Color.R, G: ht.Color.G, B: ht.Color.B, A: 100}
			offset := triangleOffsets[ht.OffsetIndex]

			// Haul type radious
			radius := ht.Radius
			mldAddr := ""
			mldBands := []string{}
			mldLinkCount := 0

			// haul type circe position and dimentions
			circlePos := fyne.NewPos(pos.X-radius+offset.X, pos.Y-radius+offset.Y)
			circleSize := fyne.NewSize(radius*2, radius*2)

			// haul info to be display inside the circle
			haulInfo := fmt.Sprintf("%s\n", ht.SSID)
			if len(ht.BSSList) > 0 {
				for _, bss := range ht.BSSList {
					if bss.VapMode != 1 {
						bandName, _ := bandToNameAndColor(bss.Band)
						if bss.MLDAddr != "" {
							mldLinkCount++
							mldAddr = bss.MLDAddr
							mldBands = append(mldBands, bandName)
						}
						if bss.Band == 0 || bss.Band == 1 {
							bss.IEEE= "802.11ax"
						} else {
							bss.IEEE= "802.11be"
						}
						haulInfo += fmt.Sprintf("\n%s - %s - %s", bss.BSSID, bandName, bss.IEEE)
					}
				}
			}
			if mldLinkCount > 0 {
				haulInfo += fmt.Sprintf("\n%s - %d (%s)", mldAddr, mldLinkCount, strings.Join(mldBands, ", "))
			}
			haulInfo += fmt.Sprintf("\nVLANID = %d\n", ht.VlanId)

			lines := strings.Split(haulInfo, "\n")

			// Circle dimensions
			diameter := radius * 2
			padding := float32(6)
			availableHeight := float64(diameter - 2*padding)

			// Font sizes and line heights
			firstLineSize := float64(12)
			otherLineSize := float64(8)
			firstLineHeight := firstLineSize + 2
			otherLineHeight := otherLineSize + 2

			// Calculate total height
			totalHeight := firstLineHeight + otherLineHeight*float64(len(lines)-1)

			// Scale down if needed
			if totalHeight > availableHeight {
				scale := availableHeight / totalHeight
				firstLineSize *= scale
				otherLineSize *= scale
				firstLineHeight = firstLineSize + 2
				otherLineHeight = otherLineSize + 2
				totalHeight = firstLineHeight + otherLineHeight*float64(len(lines)-1)
			}

			// Calculate Y positions using cumulative sum
			lineHeights := make([]float64, len(lines))
			lineHeights[0] = firstLineHeight
			for i := 1; i < len(lines); i++ {
				lineHeights[i] = otherLineHeight
			}

			yPositions := make([]float64, len(lines))
			yPositions[0] = float64(circlePos.Y) + float64(radius) - totalHeight/2
			for i := 1; i < len(lines); i++ {
				yPositions[i] = yPositions[i-1] + lineHeights[i-1]
			}

			// Render text
			for i, line := range lines {
				var textSize float32
				if i == 0 {
					textSize = float32(firstLineSize)
				} else {
					textSize = float32(otherLineSize)
				}

				text := canvas.NewText(line, color.RGBA{R: 169, G: 169, B: 169, A: 255})
				text.TextSize = textSize
				text.TextStyle = fyne.TextStyle{Bold: true}
				text.Alignment = fyne.TextAlignCenter
				text.Refresh()

				text.Move(fyne.NewPos(circlePos.X+radius, float32(yPositions[i])))
				container.Add(text)
			}

			circle := canvas.NewCircle(transparentCol)
			circle.Resize(circleSize)
			circle.Move(circlePos)
			container.Add(circle)
		}

		if meta.Icon != nil {

			image := canvas.NewImageFromResource(meta.Icon)
			image.FillMode = canvas.ImageFillContain
			image.Refresh()
			image.Resize(fyne.NewSize(meta.SymbolSize, meta.SymbolSize))
			image.Move(fyne.NewPos(pos.X-meta.SymbolSize/2, pos.Y-meta.SymbolSize/2))
			container.Add(image)
		}

		if len(meta.HaulTypes) > 0 {
			label := canvas.NewText(name, color.RGBA{R: 30, G: 30, B: 30, A: 255})
			label.TextSize = 10
			label.Refresh()

			textSize := label.MinSize()

			iconCenter := fyne.NewPos(pos.X, pos.Y)
			labelPos := fyne.NewPos(
				iconCenter.X-textSize.Width/2,
				iconCenter.Y+meta.SymbolSize/2-4,
			)

			label.Move(labelPos)
			container.Add(label)
		}

        //Calculate the node center postion
        nodeCenter := fyne.NewPos(meta.X+canvasOffset.X, meta.Y+canvasOffset.Y)

        // Total STA associated
        totalSTAs := 0
        for _, staCtx := range meta.STAList {
            if staCtx.STA.Associated {
                totalSTAs++
            }
        }

        // STAs angle steps
        angleStep := 2 * math.Pi / float64(totalSTAs)
        // minimum radius
        minRadius := float32(80)
        // maximum radius
        maxRadius := float32(120)
        minSize := float32(16)
        maxSize := float32(40)
        placedPositions := []fyne.Position{}

        //Place each STA around the node
        staIndex := 0
        for _, staCtx := range meta.STAList {
            if !staCtx.STA.Associated {
                continue
            }

            sta := staCtx.STA
            band := staCtx.Band

            // Dynamic icon size
            iconSize := maxSize - (maxSize-minSize)*float32(totalSTAs)/float32(20)
            if iconSize < minSize {
                iconSize = minSize
            }

            // Use index-based seed for consistent placement
            r := rand.New(rand.NewSource(int64(staIndex)))

            // calculating the STA position for placement
            var staPos fyne.Position
			placed := false
            for attempt := 0; attempt < 10; attempt++ {
                radius := minRadius + r.Float32()*(maxRadius-minRadius)
                if radius < minRadius {
                    radius = minRadius
                }

                angle := angleStep*float64(staIndex)
                if totalSTAs < 5 {
                    angle += r.Float64()*angleStep
                }
                offsetX := float32(math.Cos(angle)) * radius
                offsetY := float32(math.Sin(angle)) * radius
                candidatePos := fyne.NewPos(nodeCenter.X+offsetX, nodeCenter.Y+offsetY)

                // Check overlap
                overlap := false
                for _, other := range placedPositions {
                    dx := candidatePos.X - other.X
                    dy := candidatePos.Y - other.Y
                    if math.Hypot(float64(dx), float64(dy)) < float64(iconSize+4) {
                        overlap = true
                        break
                    }
                }

                if !overlap {
                    staPos = candidatePos
					placed = true
                    placedPositions = append(placedPositions, staPos)
                    break
                }
            }

            // Fallback if no valid position found
            if !placed {
                fmt.Printf("Warning: Failed to place STA %d. Using fallback position.\n", staIndex)
                fallbackRadius := maxRadius - iconSize
				fallbackAngle := 2 * math.Pi * float64(staIndex) / float64(totalSTAs)
                fallbackOffsetX := float32(math.Cos(fallbackAngle)) * fallbackRadius
                fallbackOffsetY := float32(math.Sin(fallbackAngle)) * fallbackRadius

                staPos = fyne.NewPos(nodeCenter.X+fallbackOffsetX, nodeCenter.Y+fallbackOffsetY)
                placedPositions = append(placedPositions, staPos)

            }

            // Create STA icon
            staIcon := NewClickableImage(staCtx.Icon, func() {
                info := fmt.Sprintf("%.28s\n", sta.ClientType)
                info += fmt.Sprintf("MAC: %s\n",sta.MACAddress)
                if sta.MLDAddr != "" {
                    info += fmt.Sprintf("MLD: %s\n",sta.MLDAddr)
                }
                pause_start_Timer(true)
                showTooltip(container, info, fyne.NewPos(staPos.X, staPos.Y), color.RGBA{R: 216, G: 167, B: 7, A: 255})
            })
            staIcon.Resize(fyne.NewSize(iconSize, iconSize))
            staIcon.Move(fyne.NewPos(staPos.X-iconSize/2, staPos.Y-iconSize/2))
            container.Add(staIcon)
            container.Refresh()
            // Draw sine wave connection
            staOffsetDistance := float64(iconSize) * 0.5
            nodeOffsetDistance := 30.0
            length := math.Hypot(float64(nodeCenter.X-staPos.X), float64(nodeCenter.Y-staPos.Y))
            offsetXDir := (float64(nodeCenter.X) - float64(staPos.X)) / length
            offsetYDir := (float64(nodeCenter.Y) - float64(staPos.Y)) / length

            startVec := r2.Vec{
                X: float64(staPos.X) + offsetXDir*staOffsetDistance,
                Y: float64(staPos.Y) + offsetYDir*staOffsetDistance,
            }
            endVec := r2.Vec{
                X: float64(nodeCenter.X) - offsetXDir*nodeOffsetDistance,
                Y: float64(nodeCenter.Y) - offsetYDir*nodeOffsetDistance,
            }

            bandWavelength := map[int]float64{
                0: 10.0,
                1: 8.0,
                2: 6.0,
            }
            wavelength := bandWavelength[band]
            distance := math.Hypot(endVec.X-startVec.X, endVec.Y-startVec.Y)
            cycles := distance / wavelength
            steps := int(cycles * 8.0)

            wavePoints := GenerateSineWavePoints(startVec, endVec, 5, cycles, steps)
             _, hexCol := bandToNameAndColor(band)
            col := lightenColor(parseHexColor(hexCol), 0.3)

            for i := 0; i < len(wavePoints)-1; i++ {
                p1 := fyne.NewPos(float32(wavePoints[i].X), float32(wavePoints[i].Y))
                p2 := fyne.NewPos(float32(wavePoints[i+1].X), float32(wavePoints[i+1].Y))
                lineSegment := canvas.NewLine(col)
                lineSegment.StrokeWidth = 1
                lineSegment.Position1 = p1
                lineSegment.Position2 = p2
                container.Add(lineSegment)
            }
            staIndex++
        }
	}

	for _, edge := range bandEdges {
		fromMeta := metaMap[edge.From]
		toMeta := metaMap[edge.To]

		// Find index of haul type in each node's HaulTypes
		fromIndex := -1
		toIndex := -1

		for i, ht := range fromMeta.HaulTypes {
			if ht.Name == edge.HaulType {
				fromIndex = i
				break
			}
		}

		for i, ht := range toMeta.HaulTypes {
			if ht.Name == edge.HaulType {
				toIndex = i
				break
			}
		}

		// Fallback to center if not found
		if fromIndex == -1 {
			fromIndex = 0
		}
		if toIndex == -1 {
			toIndex = 0
		}

		fromCenter := fyne.NewPos(fromMeta.X+canvasOffset.X, fromMeta.Y+canvasOffset.Y)
		toCenter := fyne.NewPos(toMeta.X+canvasOffset.X, toMeta.Y+canvasOffset.Y)

		_, hexCol := bandToNameAndColor(edge.Band)
		col := parseHexColor(hexCol)

		nodeRadius := float32(35)

		adjustedFrom := offsetFromCenter(fromCenter, toCenter, nodeRadius)
		adjustedTo := offsetFromCenter(toCenter, fromCenter, nodeRadius)

		startVec := r2.Vec{X: float64(adjustedFrom.X), Y: float64(adjustedFrom.Y)}
		endVec := r2.Vec{X: float64(adjustedTo.X), Y: float64(adjustedTo.Y)}

		// Generate sine wave points
		wavePoints := GenerateSineWavePoints(startVec, endVec, 5, 30, 200)
		midIndex := len(wavePoints) / 2
		mid := wavePoints[midIndex]
		midPos := fyne.NewPos(float32(mid.X), float32(mid.Y))

		circleRadius := float32(15)
		circleDiameter := circleRadius * 2

		for i := 0; i < midIndex-1; i++ {
			p1 := fyne.NewPos(float32(wavePoints[i].X), float32(wavePoints[i].Y))
			p2 := fyne.NewPos(float32(wavePoints[i+1].X), float32(wavePoints[i+1].Y))

			// Stop drawing if next point enters the circle
			if distance(fyne.NewPos(float32(wavePoints[i+1].X), float32(wavePoints[i+1].Y)), midPos) < circleRadius {
				break
			}

			lineSegment := canvas.NewLine(col)
			lineSegment.StrokeWidth = 2
			lineSegment.Position1 = p1
			lineSegment.Position2 = p2
			container.Add(lineSegment)
		}

		//Draw small circle for channel
		channelCircle := canvas.NewCircle(color.White)
		channelCircle.StrokeWidth = 2
		channelCircle.StrokeColor = col
		channelCircle.Resize(fyne.NewSize(circleDiameter, circleDiameter))
		channelCircle.Move(fyne.NewPos(midPos.X-circleRadius, midPos.Y-circleRadius))
		container.Add(channelCircle)

		// Channel number text inside the circle
		channelText := canvas.NewText(fmt.Sprintf("%d", edge.Channel), color.Black)
		channelText.TextSize = 10
		channelText.TextStyle = fyne.TextStyle{Bold: true}
		channelText.Refresh()

		textSize := channelText.MinSize()
		textPos := fyne.NewPos(
			midPos.X-textSize.Width/2,
			midPos.Y-textSize.Height/2,
		)
		channelText.Move(textPos)
		container.Add(channelText)

		// Draw second half of the wave
		started := false
		for i := midIndex; i < len(wavePoints)-1; i++ {
			p1 := fyne.NewPos(float32(wavePoints[i].X), float32(wavePoints[i].Y))
			p2 := fyne.NewPos(float32(wavePoints[i+1].X), float32(wavePoints[i+1].Y))

			// Wait until we're past the circle edge
			if !started {
				if distance(p1, midPos) >= circleRadius {
					started = true
				} else {
					continue
				}
			}

			lineSegment := canvas.NewLine(col)
			lineSegment.StrokeWidth = 2
			lineSegment.Position1 = p1
			lineSegment.Position2 = p2
			container.Add(lineSegment)
		}

	}
}

/* func: buildHaulTypes()
 * Description:
 * This is a helper function to create a haulTypeMap
 * returns: []HaulTypeVisual
 */
func buildHaulTypes(radioList []Radio) []HaulTypeVisual {
	haulTypeMap := make(map[string]*HaulTypeVisual)

	for _, radio := range radioList {
		for _, bss := range radio.BSSList {
			if bss.HaulType == "" {
				continue
			}

			// Initialize if not already present
			if _, exists := haulTypeMap[bss.HaulType]; !exists {
				haulTypeMap[bss.HaulType] = &HaulTypeVisual{
					Name:        bss.HaulType,
					SSID:        bss.SSID,
					VlanId:      bss.VlanId,
					Color:       colorForHaulType(bss.HaulType),
					Radius:      100.0,
					OffsetIndex: len(haulTypeMap) % len(triangleOffsets),
					BSSList:     []BSS{},
				}
			}

			// Append BSS info with Band
			haulTypeMap[bss.HaulType].BSSList = append(haulTypeMap[bss.HaulType].BSSList, BSS{
				BSSID:     bss.BSSID,
				MLDAddr:   bss.MLDAddr,
				HaulType:  bss.HaulType,
				SSID:      bss.SSID,
				VapMode:   bss.VapMode,
				Band:      radio.Band,
				VlanId:    bss.VlanId,
				IEEE:      radio.IEEE,
			})
		}
	}

	// Convert map to sorted slice
	sortedNames := make([]string, 0, len(haulTypeMap))
	for ht := range haulTypeMap {
		sortedNames = append(sortedNames, ht)
	}
	sort.Strings(sortedNames)

	haulTypes := make([]HaulTypeVisual, 0, len(sortedNames))
	for _, ht := range sortedNames {
		haulTypes = append(haulTypes, *haulTypeMap[ht])
	}

	return haulTypes
}

/* func: GenerateSineWavePoints()
 * Description:
 * generate sine wave based on amplitude, freq and steps
 * returns: NA
 */
func GenerateSineWavePoints(start, end r2.Vec, amplitude float64, frequency float64, steps int) []r2.Vec {
    var points []r2.Vec

    // Direction vector
    dir := r2.Sub(end, start)
    length := math.Hypot(dir.X, dir.Y)
    unitDir := r2.Scale(1/length, dir)

    // Perpendicular vector
    perp := r2.Vec{-unitDir.Y, unitDir.X}

    for i := 0; i <= steps; i++ {
        t := float64(i) / float64(steps)
        base := r2.Add(start, r2.Scale(t*length, unitDir))
        offset := amplitude * math.Sin(t * frequency * 2 * math.Pi)
        point := r2.Add(base, r2.Scale(offset, perp))
        points = append(points, point)
    }

    return points
}


/* func: showTooltip()
 * Description:
 * this function create the popup to display STA info on click
 * returns: NA
 */
func showTooltip(container *fyne.Container, info string, pos fyne.Position, bgColor color.Color) {
	if currentTooltipBg != nil {
		container.Remove(currentTooltipBg)
		currentTooltipBg = nil
	}
	if currentTooltipText != nil {
		container.Remove(currentTooltipText)
		currentTooltipText = nil
	}
	if currentTooltipCloseBtn != nil {
		container.Remove(currentTooltipCloseBtn)
		currentTooltipCloseBtn = nil
	}

	// Create label
	label := widget.NewLabel(info)
	label.Wrapping = fyne.TextWrapWord
	label.TextStyle = fyne.TextStyle{Bold: true}
	label.Resize(fyne.NewSize(225, label.MinSize().Height-20))

	// Calculate position
	screenSize := container.Size()
	tooltipSize := label.Size()
	tooltipPos := fyne.NewPos(pos.X, pos.Y-tooltipSize.Height-10)

	// Clamp position to screen
	if tooltipPos.X+tooltipSize.Width > screenSize.Width {
		tooltipPos.X = screenSize.Width - tooltipSize.Width - 10
	}
	if tooltipPos.X < 0 {
		tooltipPos.X = 10
	}
	if tooltipPos.Y < 0 {
		tooltipPos.Y = pos.Y + 10
	}
	if tooltipPos.Y+tooltipSize.Height > screenSize.Height {
		tooltipPos.Y = screenSize.Height - tooltipSize.Height - 50
	}

	// Background rectangle
	bg := canvas.NewRectangle(bgColor)
	bg.Resize(tooltipSize.Add(fyne.NewSize(20, 20))) // Smaller padding
	bg.Move(tooltipPos.Subtract(fyne.NewPos(10, 10)))
	container.Add(bg)
	currentTooltipBg = bg

	// Add label
	label.Move(tooltipPos)
	container.Add(label)
	currentTooltipText = label

	// Create close button safely
	var closeBtn *widget.Button
	closeBtn = widget.NewButtonWithIcon("", theme.CancelIcon(), nil)
	closeBtn.OnTapped = func() {
		container.Remove(currentTooltipBg)
		container.Remove(currentTooltipText)
		container.Remove(closeBtn)
		pause_start_Timer(false)
		currentTooltipBg = nil
		currentTooltipText = nil
		currentTooltipCloseBtn = nil
	}
	closeBtn.Resize(fyne.NewSize(20, 20))
	closeBtn.Move(fyne.NewPos(
		tooltipPos.X+tooltipSize.Width-10,
		tooltipPos.Y-10,
	))
	container.Add(closeBtn)
	currentTooltipCloseBtn = closeBtn
}

/* func: getBandsFromRadioList()
 * Description:
 * this function create a map of bands with respect to radioList
 * returns: NA
 */
func getBandsFromRadioList(radios []Radio) []Band {
	defaultBands := getDefaultBands()
	bandMap := make(map[int]Band)
	for i, band := range defaultBands {
		bandMap[i] = band
	}

	seen := make(map[int]bool)
	var bands []Band
	for _, radio := range radios {
		if !seen[radio.Band] {
			if band, ok := bandMap[radio.Band]; ok {
				bands = append(bands, band)
				seen[radio.Band] = true
			}
		}
	}
	return bands
}

/* func: parseSTA()
 * Description:
 * this function Parse the necessary info from STA node and set the STA struct
 * returns: NA
 */
func parseSTA(node *C.em_network_node_t) STA {
	var associated bool
	if getTreeValue(node, "Associated") == "true" {
		associated = true
	} else {
		associated =  false
	}
    return STA{
        MACAddress: getTreeValue(node, "MACAddress"),
        ClientType: getTreeValue(node, "ClientType"),
		Associated: associated,
    }
}

/* func: parseRadioList()
 * Description:
 * this function Parse the necessary info from Radio node
 * returns: []Radio
 */
func parseRadioList(tree *C.em_network_node_t) []Radio {
    var radios []Radio
    if tree == nil {
        return radios
    }

    for i := 0; i < int(tree.num_children); i++ {
        radio := tree.child[i]
        if radio == nil {
            continue
        }

        bssNode := C.get_network_tree_by_key(radio, C.CString("BSSList"))
        var bssList []BSS
        for j := 0; j < int(bssNode.num_children); j++ {
            bss := bssNode.child[j]
            if bss == nil {
                continue
            }

            staNode := C.get_network_tree_by_key(bss, C.CString("STAList"))
            var staList []STA
            for k := 0; k < int(staNode.num_children); k++ {
                sta := staNode.child[k]
                if sta != nil {
                    staList = append(staList, parseSTA(sta))
                }
            }

            bssList = append(bssList, BSS{
				BSSID:    getTreeValue(bss, "BSSID"),
				MLDAddr:  getTreeValue(bss, "MLDAddr"),
                SSID:     getTreeValue(bss, "SSID"),
                HaulType: getTreeValue(bss, "HaulType"),
                VapMode:  getKeyIntValue(bss, "VapMode"),
                Band:     getKeyIntValue(bss, "Band"),
                VlanId:   getKeyIntValue(bss, "VlanID"),
                STAList:  staList,
            })
        }

        radios = append(radios, Radio{
            ID:                 getTreeValue(radio, "ID"),
            Enabled:            getKeyIntValue(radio, "Enabled") == 1,
            Band:               getKeyIntValue(radio, "Band"),
            IEEE:               getTreeValue(radio, "IEEE"),
            BSSList:            bssList,
        })
    }
    return radios
}

/* func: getBandFromRadioTree()
 * Description:
 * this function Parse the RadioList node and get the band info
 * returns: band
 */
func getBandAndChannelFromRadioTree(node *C.em_network_node_t) (int, int) {

	// Iterate through the radiolist child
	for i := 0; i < int(node.num_children); i++ {
        radio := node.child[i]
        if radio == nil {
            continue
        }

		// BSSList node
        bssListNode := C.get_network_tree_by_key(radio, C.CString("BSSList"))
        for i := 0; i < int(bssListNode.num_children); i++ {
            bss := bssListNode.child[i]
		    vapMode := getKeyIntValue(bss, "VapMode")
            if vapMode == 1 {
				// return the band if vapMode is set
                return getKeyIntValue(radio, "Band") , getKeyIntValue(radio, "Channel")
            }
        }
    }
	// If no valid connected band found
    return -1, 0
}

/* func: lightenColor()
 * Description:
 * Helper function to make the sinwave line little lighter for STA
 * returns: color.RGBA
 */
func lightenColor(c color.Color, factor float64) color.RGBA {
    rgba, ok := c.(color.RGBA)
    if !ok {
        // fallback if color is not RGBA
        r, g, b, a := c.RGBA()
        rgba = color.RGBA{
            R: uint8(r >> 8),
            G: uint8(g >> 8),
            B: uint8(b >> 8),
            A: uint8(a >> 8),
        }
    }

    return color.RGBA{
        R: uint8(float64(rgba.R) + (255-float64(rgba.R))*factor),
        G: uint8(float64(rgba.G) + (255-float64(rgba.G))*factor),
        B: uint8(float64(rgba.B) + (255-float64(rgba.B))*factor),
        A: rgba.A,
    }
}

/* func: offsetFromCenter()
 * Description:
 * Helper function to calculate the offset from center
 * returns: fyne.Position
 */
func offsetFromCenter(start, end fyne.Position, offset float32) fyne.Position {
	dx := end.X - start.X
	dy := end.Y - start.Y
	length := float32(math.Hypot(float64(dx), float64(dy)))

	if length == 0 {
		return start
	}

	// Normalize and scale
	nx := dx / length
	ny := dy / length

	return fyne.NewPos(start.X+nx*offset, start.Y+ny*offset)
}

/* func: colorForHaulType()
 * Description:
 * Helper function for haultype color mapping
 * returns: fyne.Position
 */
func colorForHaulType(haulType string) color.RGBA {
	switch haulType {
	case "Backhaul":
		return color.RGBA{R: 80, G: 30, B: 30, A: 230}
	case "Fronthaul":
		return color.RGBA{R: 60, G: 70, B: 120, A: 230}
	case "Mesh":
		return color.RGBA{R: 90, G: 60, B: 100, A: 230}
	default:
		return color.RGBA{R: 70, G: 70, B: 70, A: 230}
	}
}

/* func: getDefaultBands()
 * Description:
 * Helper function for band color mapping
 * returns: NA
 */
func getDefaultBands() []Band {
	return []Band{
		{Name: "2.4GHz", Color: "#8B4513"},
		{Name: "5GHz", Color: "#5a82c2ff"},
		{Name: "6GHz", Color: "#e60808ff"},
	}
}

/* func: bandToNameAndColor()
 * Description:
 * Helper function to get band name and respective color based on radio index
 * returns: name, color
 */
func bandToNameAndColor(index int) (string, string) {
	bands := getDefaultBands()
	if index >= 0 && index < len(bands) {
		return bands[index].Name, bands[index].Color
	}
	return "Unknown", "#808080" // Default gray for unknown band
}

/* func: distance()
 * Description:
 * Helper function to calculate the devaition from node
 * returns: fyne.Position
 */
func distance(a, b fyne.Position) float32 {
	dx := a.X - b.X
	dy := a.Y - b.Y
	return float32(math.Hypot(float64(dx), float64(dy)))
}

/* func: parseHexColor()
 * Description:
 * Helper function to convert hex colorto color.Color format
 * returns: fyne.Position
 */
func parseHexColor(s string) color.Color {
	c, err := colorful.Hex(s)
	if err != nil {
		return color.Black
	}
	r, g, b := c.RGB255()
	return color.RGBA{R: r, G: g, B: b, A: 255}
}

/* func: printBandEdges()
 * Description:
 * Helper function to print BandEdge array data
 * returns: fyne.Position
 */
func printBandEdges(edges []BandEdge) {
	for _, edge := range edges {
		fmt.Printf("From: %s, To: %s, Band: %d\n", edge.From, edge.To, edge.Band)
	}
}

/* func: printRawNodes()
 * Description:
 * Helper function to print RawNode array data
 * returns: fyne.Position
 */
func printRawNodes(metaMap map[string]RawNode) {
	for _, node := range metaMap {
		fmt.Printf("Node: %s\n", node.Name)
		fmt.Printf("  Position: (%.2f, %.2f)\n", node.X, node.Y)
		fmt.Printf("  Symbol Size: %.2f\n", node.SymbolSize)
		fmt.Printf("  HaulType:\n")
		for _, ht := range node.HaulTypes {
			fmt.Printf("    - %s (Color: %s, Radius: %.2f)\n", ht.Name, ht.Color, ht.Radius)
		}
		fmt.Printf("  STAList:\n")
		for _, ht := range node.STAList {
			fmt.Printf("    - %s \n", ht.STA.MACAddress)
		}
		fmt.Println()
	}
}

func (c *Concentric) MinSize(objects []fyne.CanvasObject) fyne.Size {
	w, h := float32(50), float32(50)
	return fyne.NewSize(w, h)
}

func (c *Concentric) Layout(objects []fyne.CanvasObject, containerSize fyne.Size) {
	/*var angle, incr, radius float64
	centerX := containerSize.Width / 2
	centerY := containerSize.Height / 2
	cX := centerX - c.MinSize(objects).Width/2
	cY := centerY - c.MinSize(objects).Height/2

	if len(objects) > 0 {
		objects[0].Move(fyne.NewPos(cX, cY))
	}

	angle = 0
	incr = 30
	radius = 100

	for i := 1; i < len(objects); i++ {
		switch obj := objects[i].(type) {
		case *canvas.Image:
			X := radius * math.Cos(angle*math.Pi/180)
			Y := radius * math.Sin(angle*math.Pi/180)
			angle += incr
			if angle >= 360 {
				radius += 70
				incr += 2
				angle = 0
			}
			pos := fyne.NewPos(cX+float32(X), cY+float32(Y))
			obj.Move(pos)
		case *canvas.Text:
			obj.Move(objects[i-1].Position())
		case *canvas.Line:
			obj.Position1 = objects[0].Position()
			obj.Position2 = objects[i-2].Position()
			obj.Move(obj.Position())
		case *canvas.Raster:
			obj.Move(objects[0].Position())
		}
	}*/
}

/* func: periodicTimer()
 * Description:
 * periodicTimer is being called by timer to fetch
 * and update the topology graph periodically
 * returns: NA
 */
func (t *Topology) periodicTimer() {
	// local variable
	var (
        jsonFile  string
        err       error
        g         *simple.UndirectedGraph
        nodeMap   map[string]graph.Node
        metaMap   map[string]RawNode
        bandEdges []BandEdge
    )

	// Draw the graph based on static json files
	if len(os.Args) > 1 && os.Args[1] == "test" {
        jsonFile = getTestJSONFile(t.timerCount)
	    g, nodeMap, metaMap, bandEdges, err = loadNestedTopologyJSON(jsonFile, t.topo)

	} else {
		// Fetch the live data and draw the graph based live data
		topologyTree := t.getData()
		if topologyTree == nil || getTreeValue(topologyTree, "Status") != "Success" {
			log.Printf("Failed to get the network topology")
			return
		}

		// Fetch the Devoce node
		topoDeviceTree := C.get_network_tree_by_key(topologyTree, C.CString("Device"))
		if topoDeviceTree == nil {
			log.Printf("Failed to get the network topology")
			return
		}

		// Call the helper function to parse set the structure.
		g, nodeMap, metaMap, bandEdges, err = loadNestedTopologyFromDeviceTree(topoDeviceTree, t.topo)
	}

	// Validate if any error while parsing
	if err != nil {
		log.Printf("Error loading topology: %v", err)
		return
	}

	// Debug Helper function to print the links
	//printBandEdges(bandEdges)
	//printRawNodes(metaMap)
	
	// Clear previous graph
	t.topo.Objects = nil
	t.topo.Refresh()
	// Draw the graph
	drawNetworkTopologyGraph(g, nodeMap, metaMap, bandEdges, t.topo)

	t.topo.Refresh()
}
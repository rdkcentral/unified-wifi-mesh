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
	NumberOfBSS        int    `json:"NumberOfBSS"`
	NumberOfUnassocSta int    `json:"NumberOfUnassocSta"`
	Noise              int    `json:"Noise"`
	Utilization        int    `json:"Utilization"`
	Band               int    `json:"Band"`
	IEEE               string `json:"IEEE"`
	BSSList            []BSS  `json:"BSSList"`
}

type BSS struct {
	BSSID     string `json:"BSSID"`
	HaulType  string `json:"HaulType"`
	VlanId    int    `json:"VlanId"`
	SSID      string `json:"SSID"`
	Enabled   bool   `json:"Enabled"`
	TimeStamp string `json:"TimeStamp"`
	VapMode   int    `json:"VapMode"`
	Band      int    `json:"Band"`
	IEEE      string `json:"IEEE"`
	Channel   int    `json:"Channel"`
	STAList   []STA  `json:"STAList"`
}

type STA struct {
	MACAddress     string `json:"MACAddress"`
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

func getIconForClientType(clientType string) fyne.Resource {
    lower := strings.ToLower(clientType)

    switch {
    case strings.Contains(lower, "iphone"):
        return resourceIphonePng
    case strings.Contains(lower, "ipad"):
        return resourceIpadPng
    case strings.Contains(lower, "android"):
        return resourceAndroidPng
    default:
        return  resourceAndroidPng// fallback icon
    }

}

func loadNestedTopologyJSON(path string, container *fyne.Container) (*simple.UndirectedGraph, map[string]graph.Node, map[string]RawNode, []BandEdge, error) {
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

	var traverse func(device Device, parentX, parentY float32, baseAngle float64)
	traverse = func(device Device, parentX, parentY float32, baseAngle float64) {
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

				if child.ID == "ea:f6:db:3b:bb:71" {
					childY -= 130
					childX -= 50
				}

				if child.ID == "e2:42:20:03:25:a5" {
					childY += 130 // Move Extender 1 upward by 50 pixels
					childX -= 50
				}

				if child.ID == "e2:42:20:03:25:a6" {
					childY -= 80 // Move Extender 1 upward by 50 pixels
					childX += 60
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
						channel = bss.Channel
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

			traverse(child, metaMap[device.ID].X, metaMap[device.ID].Y, childAngle)
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

	traverse(*rootDevice, 0, 0, 0)
	return g, nodeMap, metaMap, bandEdges, nil
}

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
					Color:       colorForHaulType(bss.HaulType),
					Radius:      100.0,
					OffsetIndex: len(haulTypeMap) % len(triangleOffsets),
					BSSList:     []BSS{},
				}
			}

			// Append BSS info with Band
			haulTypeMap[bss.HaulType].BSSList = append(haulTypeMap[bss.HaulType].BSSList, BSS{
				BSSID:     bss.BSSID,
				HaulType:  bss.HaulType,
				SSID:      bss.SSID,
				Enabled:   bss.Enabled,
				TimeStamp: bss.TimeStamp,
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


type ClickableImage struct {
    widget.BaseWidget
    image    *canvas.Image
    onTapped func()
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

func drawEChartsGraph(
	g *simple.UndirectedGraph,
	nodeMap map[string]graph.Node,
	metaMap map[string]RawNode,
	bandEdges []BandEdge,
	container *fyne.Container,
) {
	idToName := make(map[int64]string)

	canvasSize := container.Size()
	canvasOffset := fyne.NewPos(canvasSize.Width/2, canvasSize.Height/2)

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

		for _, ht := range meta.HaulTypes {
			transparentCol := color.RGBA{R: ht.Color.R, G: ht.Color.G, B: ht.Color.B, A: 100}

			offset := triangleOffsets[ht.OffsetIndex]

			radius := ht.Radius

			circlePos := fyne.NewPos(pos.X-radius+offset.X, pos.Y-radius+offset.Y)
			circleSize := fyne.NewSize(radius*2, radius*2)

			haulInfo := fmt.Sprintf("%s\n", ht.Name)
			if ht.Name == "Fronthaul" {
				ht.VlanId = 12
			} else if ht.Name == "Backhaul" {
				ht.VlanId = 13
			} else if ht.Name == "Iot" {
				ht.VlanId = 11
			}

			if len(ht.BSSList) > 0 {
				for _, bss := range ht.BSSList {
					if bss.VapMode != 1 {
						bandName, _ := bandToNameAndColor(bss.Band)
						haulInfo += fmt.Sprintf("\n%s - %s - %s", bss.BSSID, bandName, bss.IEEE)
					}
				}
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
			//circleCenter := fyne.NewPos(meta.X+canvasOffset.X+offset.X, meta.Y+canvasOffset.Y+offset.Y)
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

		// Draw associated STAs inside HaulType circle and connect to node icon
		for _, staCtx := range meta.STAList {
			if !staCtx.STA.Associated {
				continue
			}

			sta := staCtx.STA
			band := staCtx.Band

			// Find the HaulType circle center for this STA
			var haulCenter fyne.Position
			var radius float32
			for _, ht := range meta.HaulTypes {
				if ht.Name == staCtx.HaulType {
					offset := triangleOffsets[ht.OffsetIndex]
					haulCenter = fyne.NewPos(meta.X+canvasOffset.X+offset.X, meta.Y+canvasOffset.Y+offset.Y)
					radius = ht.Radius
					break
				}
			}

			// Place STA inside the HaulType circle using a radial offset
			// You can use index-based offset or random angle for distribution
			staIndex := 1 // or use a loop index if available
			totalSTAs := len(meta.STAList)
			angle := 2 * math.Pi * float64(staIndex) / float64(totalSTAs)

			staOffsetX := float32(math.Cos(angle)) * (radius - 20)
			staOffsetY := float32(math.Sin(angle)) * (radius - 20)
			staPos := fyne.NewPos(haulCenter.X+staOffsetX-70, haulCenter.Y+staOffsetY+50)

			staIcon := NewClickableImage(staCtx.Icon, func() {
				info := fmt.Sprintf("%s\nMAC: %s\n", sta.ClientType, sta.MACAddress)
				pause_start_Timer(true)
				showTooltip(container, info, fyne.NewPos(staPos.X, staPos.Y), color.RGBA{R: 216, G: 167, B: 7, A: 255})
			})
			staIcon.Resize(fyne.NewSize(40, 40)) // Ensure it's visible
			staIcon.Move(fyne.NewPos(staPos.X-20, staPos.Y-20)) // Adjust position
			container.Add(staIcon)
			container.Refresh()


			// Connect sinewave from STA to node icon (not HaulType)
			nodeCenter := fyne.NewPos(meta.X+canvasOffset.X, meta.Y+canvasOffset.Y)

			// Compute direction vector from STA to Node
			dx := float64(nodeCenter.X - staPos.X)
			dy := float64(nodeCenter.Y - staPos.Y)
			length := math.Hypot(dx, dy)

			// Normalize and scale offset
			staOffsetDistance := 25.0  // STA side offset
			nodeOffsetDistance := 30.0 // Node side offset (slightly more)

			offsetX := dx / length
			offsetY := dy / length

			// Apply offset to start and end points
			startVec := r2.Vec{
				X: float64(staPos.X) + offsetX*staOffsetDistance,
				Y: float64(staPos.Y) + offsetY*staOffsetDistance,
			}
			endVec := r2.Vec{
				X: float64(nodeCenter.X) - offsetX*nodeOffsetDistance,
				Y: float64(nodeCenter.Y) - offsetY*nodeOffsetDistance,
			}

			wavePoints := GenerateSineWavePoints(startVec, endVec, 6, 10, 100)

			_, hexCol := bandToNameAndColor(band)
			col := parseHexColor(hexCol)
			col = lightenColor(col, 0.3)
			for i := 0; i < len(wavePoints)-1; i++ {
				p1 := fyne.NewPos(float32(wavePoints[i].X), float32(wavePoints[i].Y))
				p2 := fyne.NewPos(float32(wavePoints[i+1].X), float32(wavePoints[i+1].Y))
				lineSegment := canvas.NewLine(col)
				lineSegment.StrokeWidth = 1
				lineSegment.Position1 = p1
				lineSegment.Position2 = p2
				container.Add(lineSegment)
			}
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

		nodeRadius := float32(35) // Adjust based on your icon size

		adjustedFrom := offsetFromCenter(fromCenter, toCenter, nodeRadius)
		adjustedTo := offsetFromCenter(toCenter, fromCenter, nodeRadius)

		startVec := r2.Vec{X: float64(adjustedFrom.X), Y: float64(adjustedFrom.Y)}
		endVec := r2.Vec{X: float64(adjustedTo.X), Y: float64(adjustedTo.Y)}

		// Generate sine wave points
		wavePoints := GenerateSineWavePoints(startVec, endVec, 5, 30, 200) // amplitude=20, frequency
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
	label.Resize(fyne.NewSize(200, label.MinSize().Height-20))

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
		base := r2.Add(start, r2.Scale(t, dir))
		offset := amplitude * math.Sin(t*frequency*2*math.Pi)
		wavePoint := r2.Add(base, r2.Scale(offset, perp))
		points = append(points, wavePoint)
	}

	return points
}

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

func printBandEdges(edges []BandEdge) {
	for _, edge := range edges {
		fmt.Printf("From: %s, To: %s, Haul: %s\n", edge.From, edge.To, edge.HaulType)
	}
}

func parseHexColor(s string) color.Color {
	c, err := colorful.Hex(s)
	if err != nil {
		return color.Black
	}
	r, g, b := c.RGB255()
	return color.RGBA{R: r, G: g, B: b, A: 255}
}

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

func getDefaultBands() []Band {
	return []Band{
		{Name: "2.4GHz", Color: "#8B4513"},
		{Name: "5GHz", Color: "#5a82c2ff"},
		{Name: "6GHz", Color: "#CD5C5C"},
	}
}

func bandToNameAndColor(index int) (string, string) {
	bands := getDefaultBands()
	if index >= 0 && index < len(bands) {
		return bands[index].Name, bands[index].Color
	}
	return "Unknown", "#808080" // Default gray for unknown band
}

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

func distance(a, b fyne.Position) float32 {
	dx := a.X - b.X
	dy := a.Y - b.Y
	return float32(math.Hypot(float64(dx), float64(dy)))
}

func (t *Topology) periodicTimer() {
	// Clear previous graph
	var jsonFile string

	t.topo.Objects = nil
	t.topo.Refresh()
	t.timerCount++

	if t.timerCount <= 3 {
	jsonFile = "../../src/fynecli/example/network_topo.json"
	} else if t.timerCount > 3 && t.timerCount <= 6 {
		jsonFile = "../../src/fynecli/example/network_topo1.json"
	} else if t.timerCount > 6 && t.timerCount <= 9 {
		jsonFile = "../../src/fynecli/example/network_topo2.json"
	} else if t.timerCount > 9 && t.timerCount <= 12 {
		jsonFile = "../../src/fynecli/example/network_topo3.json"
	} else {
		t.timerCount = 0
		jsonFile = "../../src/fynecli/example/network_topo.json"
	}

	g, nodeMap, metaMap, bandEdges, err := loadNestedTopologyJSON(jsonFile, t.topo)

	//printBandEdges(bandEdges)
	//printRawNodes(metaMap)
	if err != nil {
		log.Printf("Error loading topology: %v", err)
		return
	}

	drawEChartsGraph(g, nodeMap, metaMap, bandEdges, t.topo)

	t.topo.Refresh()

}

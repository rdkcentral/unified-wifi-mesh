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
	"image/color"
	"log"
	"math"

	"fyne.io/fyne/v2"

	//    "fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/canvas"
)

type Concentric struct {
}

func (c *Concentric) MinSize(objects []fyne.CanvasObject) fyne.Size {
	w, h := float32(50), float32(50)
	return fyne.NewSize(w, h)
}

func (c *Concentric) Layout(objects []fyne.CanvasObject, containerSize fyne.Size) {
	var pos fyne.Position
	var X, Y, angle, incr, radius float64

	w, h := containerSize.Width/2, containerSize.Height/2
	cX := w - c.MinSize(objects).Width/2
	cY := h - c.MinSize(objects).Height/2
	cPos := fyne.NewPos(w-c.MinSize(objects).Width/2, h-c.MinSize(objects).Height/2)
	objects[0].Move(cPos)

	angle = 0
	incr = 30
	radius = 100

	for i := 1; i < len(objects); i++ {
		if _, ok := objects[i].(*canvas.Image); ok {

			X = radius * math.Cos(angle*math.Pi/180)
			Y = radius * math.Sin(angle*math.Pi/180)

			angle += incr
			if angle >= 360 {
				radius += 70
				incr += 2
				angle = 0
			}

			log.Printf("Object[%d]: Angle:%f\tX:%f\tY:%f", i, angle, X, Y)

			pos = fyne.NewPos(cX+float32(X), cY+float32(Y))
			objects[i].Move(pos)
		} else if _, ok := objects[i].(*canvas.Text); ok {
			log.Printf("Object[%d]: Text", i)
			objects[i].Move(objects[i-1].Position())
		} else if line, ok := objects[i].(*canvas.Line); ok {
			log.Printf("Object[%d]: Line", i)
			line.Position1 = objects[0].Position()
			line.Position2 = objects[i-2].Position()
			objects[i].Move(objects[i].Position())
		} else if _, ok := objects[i].(*canvas.Raster); ok {
			log.Printf("Object[%d]: Raster", i)
			objects[i].Move(objects[0].Position())
		}
	}
}

func (t *Topology) periodicTimer() {
	image := canvas.NewImageFromResource(resourceExtenderPng)
	image.Resize(fyne.Size{Width: 30, Height: 30})
	t.topo.Add(image)

	text := canvas.NewText("Extender", color.White)
	text.TextSize = 10
	t.topo.Add(text)

	/*
		line := canvas.NewLine(color.White)
		line.StrokeWidth = 1
		t.topo.Add(line)

	*/
	image = canvas.NewImageFromFile("./wifilink.png")
	//raster := canvas.NewRasterFromImage(image)
	//t.topo.Add(raster)
}

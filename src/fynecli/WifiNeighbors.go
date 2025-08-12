package main

import "C"

func (s *WifiNeighbors) periodicTimer() {
    s.obj.Refresh()
}

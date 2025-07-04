package main

import "C"

func (s *ClientDevice) periodicTimer() {
    s.obj.Refresh()
}

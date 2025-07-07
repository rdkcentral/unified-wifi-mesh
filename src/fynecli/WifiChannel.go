package main

import "C"

func (s *WifiChannel) periodicTimer() {
    s.obj.Refresh()
}

package main

import "C"

func (s *WifiRadio) periodicTimer() {
    s.obj.Refresh()
}

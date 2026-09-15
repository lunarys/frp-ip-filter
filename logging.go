package main

import "log"

func (s *server) logAccess(format string, args ...any) {
	if !s.logging.accessLog {
		return
	}
	log.Printf("access: "+format, args...)
}

func (s *server) logFrpDebug(format string, args ...any) {
	if !s.logging.frpDebug {
		return
	}
	log.Printf("frp-debug: "+format, args...)
}

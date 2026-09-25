package server

import "log"

func (s *Server) logAccess(format string, args ...any) {
	if !s.logging.AccessLog {
		return
	}
	log.Printf("access: "+format, args...)
}

func (s *Server) logFrpDebug(format string, args ...any) {
	if !s.logging.FrpDebug {
		return
	}
	log.Printf("frp-debug: "+format, args...)
}

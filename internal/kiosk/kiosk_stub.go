//go:build !kiosk

package kiosk

import (
	"context"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

// stubManager is returned when kiosk mode is not compiled in.
type stubManager struct {
	log *logging.Logger
}

// New returns a kiosk manager. When compiled without -tags kiosk,
// this returns a stub that errors if Run is called.
func New(cfg Config, log *logging.Logger, onStatus StatusFunc) (Manager, error) {
	return &stubManager{log: log}, nil
}

func (s *stubManager) Run(ctx context.Context) error {
	if s.log != nil {
		s.log.Error("kiosk mode enabled but binary compiled without -tags kiosk")
	}
	return ErrKioskNotSupported
}

func (s *stubManager) SetContent(c Content) error {
	return ErrKioskNotSupported
}

func (s *stubManager) Status() Status {
	return NewStatus(false, false, Content{Kind: "blank"}, "kiosk not supported in this build")
}

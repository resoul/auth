package clock

import (
	"time"

	"airlance.org/auth/internal/application/port"
)

var _ port.Clock = System{}

// System reads the wall clock and returns UTC times.
type System struct{}

// Now returns the current time in UTC.
func (System) Now() time.Time { return time.Now().UTC() }

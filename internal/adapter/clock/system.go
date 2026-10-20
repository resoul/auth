package clock

import (
	"time"

	"go.airlance.org/auth/internal/application/port"
)

var _ port.Clock = System{}

type System struct{}

func (System) Now() time.Time {
	return time.Now().UTC()
}

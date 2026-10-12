package port

import "time"

// Clock supplies the current time.
type Clock interface {
	Now() time.Time
}

package port

import "errors"

// ErrNotFound reports that a repository has no such record.
var ErrNotFound = errors.New("not found")

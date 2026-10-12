package admin

import "airlance.org/auth/internal/domain/identity"

// userRef is the user an act is about; the zero value is no user (an invitation names an address, not a user).
type userRef struct{ id identity.UserID }

func about(id identity.UserID) userRef { return userRef{id: id} }

var noUser = userRef{}

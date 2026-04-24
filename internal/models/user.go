package models

import (
	"time"
)

type User struct {
	ID           string     `gorm:"primaryKey;type:uuid" json:"id"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	LastSignInAt *time.Time `gorm:"column:last_sign_in_at" json:"last_login"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (User) TableName() string {
	return "auth.users"
}

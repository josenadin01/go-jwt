package models

import "gorm.io/gorm"

type User struct {
	gorm.Model        // declares ID, CreatedAt, UpdatedAt and DeletedAt
	Email      string `gorm:"unique"`
	Password   string
}

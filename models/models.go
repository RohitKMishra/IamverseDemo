package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GenerateISOString generates a time string equivalent to Date.now().toISOString in JavaScript
func GenerateISOString() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.999Z07:00")
}

// Base contains common columns for all tables
type Base struct {
	ID        uint      `gorm:"not null;unique;autoIncrement:true"`
	UUID      uuid.UUID `json:"uuid" gorm:"type:uuid;primaryKey;unique;autoIncrement:false"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

// BeforeCreate will set Base struct before every insert
func (base *Base) BeforeCreate(tx *gorm.DB) error {
	// uuid.New() creates a new random UUID or panics.
	base.UUID = uuid.New()

	// generate timestamps
	t := GenerateISOString()
	base.CreatedAt, base.UpdatedAt = t, t

	return nil
}

// AfterUpdate will update the Base struct after every update
func (base *Base) AfterUpdate(tx *gorm.DB) error {
	// update timestamps
	base.UpdatedAt = GenerateISOString()
	return nil
}

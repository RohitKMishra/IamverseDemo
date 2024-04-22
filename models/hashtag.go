package models

import "github.com/google/uuid"

type Hashtag struct {
	HashtagID uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"hashtag_id"`
	Name      string    `gorm:"uniqueIndex" json:"name"`
	Posts     []Post    `gorm:"many2many:post_hashtags;" json:"posts"`
}

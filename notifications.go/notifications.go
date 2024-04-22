// notifications/notifications.go

package notifications

import (
	"github.com/google/uuid"
	"time"
)

type Notification struct {
	NotificationID uuid.UUID `json:"notification_id" gorm:"primaryKey;not null;unique;"`
	RecipientID    uuid.UUID `json:"recipient_id" gorm:"primaryKey;type:uuid;not null"`
	Type           string    `json:"type"`
	Message        string    `json:"message"`
	IsRead         bool      `json:"is_read"`
	CreatedAt      time.Time `json:"created_at"`
	URL            string
}

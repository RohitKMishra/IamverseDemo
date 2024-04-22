package util

import (
	"time"

	db "github.com/RohitKMishra/IamverseDemo/database"
	"github.com/RohitKMishra/IamverseDemo/notifications.go"
)

// DeleteOldNotifications deletes notifications older than the specified duration
func DeleteOldNotifications() error {
	// Calculate the date two days ago
	twoDaysAgo := time.Now().Add(-48 * time.Hour) // 48 hours to ensure two full days

	// Execute the delete query
	result := db.DB.Where("created_at < ?", twoDaysAgo).Delete(&notifications.Notification{})
	if result.Error != nil {
		return result.Error
	}

	return nil
}

package services

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/RohitKMishra/IamverseDemo/notifications.go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DBHandler defines methods for interacting with the database.
type DBHandler interface {
	SaveNotification(notification *notifications.Notification) error
	DeleteNotification(recipientID, notificationID uuid.UUID) error
	GetNotificationByID(recipientID, notificationID uuid.UUID) (*notifications.Notification, error)
	// Add other database-related methods as needed
}

// NotificationService represents a service for sending various types of notifications.
type NotificationServiceImpl struct {
	mu            sync.Mutex
	notifications []notifications.Notification
	dbHandler     DBHandler // Add a field for the DBHandler
}

// NewNotificationService creates a new instance of the NotificationServiceImpl.
func NewNotificationService(dbHandler DBHandler) *NotificationServiceImpl {
	return &NotificationServiceImpl{
		notifications: make([]notifications.Notification, 0),
		dbHandler:     dbHandler,
	}
}

// SendNotification sends a general notification to the service.
func (ns *NotificationServiceImpl) SendNotification(recipientID uuid.UUID, message, notificationType string, url string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	fmt.Println("URL FROM POST ", url)
	notification := notifications.Notification{
		NotificationID: uuid.New(),
		RecipientID:    recipientID,
		Type:           notificationType,
		Message:        message,
		IsRead:         false,
		CreatedAt:      time.Now(),
		URL:            url,
	}
	fmt.Println("Notification sent wilt url", notification.URL)
	ns.notifications = append(ns.notifications, notification)

	// Logic to store the notification in your database.
	if err := ns.dbHandler.SaveNotification(&notification); err != nil {
		// Handle the error if storing in the database fails
		fmt.Printf("Failed to store notification in the database: %v\n", err)
		// You might want to log the error or return an error response to the client
		return
	}
	fmt.Printf("Notification sent: %s (Type: %s) to recipient: %s\n", message, notificationType, recipientID)
}

// GetNotifications returns a list of notifications for a specific recipient.
func (ns *NotificationServiceImpl) GetNotifications(recipientID uuid.UUID) []notifications.Notification {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	recipientNotifications := []notifications.Notification{}
	for _, notification := range ns.notifications {
		if notification.RecipientID == recipientID {
			recipientNotifications = append(recipientNotifications, notification)
		}
	}

	return recipientNotifications
}

// Implement specific notification methods based on the provided `Type` field in the Notification struct.
// For example, you can add methods like SendGroupPostNotification, SendJobNotification, SendLikeNotification, etc.

// SetNotificationAsRead marks a notification as read for a specific recipient.
func (ns *NotificationServiceImpl) SetNotificationAsRead(recipientID uuid.UUID, notificationID uuid.UUID) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for i := range ns.notifications {
		if ns.notifications[i].RecipientID == recipientID && ns.notifications[i].NotificationID == notificationID {
			ns.notifications[i].IsRead = true

			// Update the notification's "IsRead" status in the database
			notification := &ns.notifications[i]
			if err := ns.dbHandler.SaveNotification(notification); err != nil {
				// Handle the error if updating in the database fails
				return err
			}

			break
		}
	}

	return nil
}

// SendJobRecommendation sends a job recommendation notification to the user.
func (ns *NotificationServiceImpl) SendJobRecommendation(recipientID uuid.UUID, jobDetails string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	notification := notifications.Notification{
		NotificationID: uuid.New(),
		RecipientID:    recipientID,
		Type:           "JobRecommendation",
		Message:        "New job recommendation: " + jobDetails,
		IsRead:         false,
		CreatedAt:      time.Now(),
	}

	// Save the job recommendation notification in the database
	if err := ns.dbHandler.SaveNotification(&notification); err != nil {
		return err
	}

	// Append the notification to the in-memory slice
	ns.notifications = append(ns.notifications, notification)

	// Here, you can implement additional logic to send the notification to the recipient if needed.

	fmt.Printf("Job recommendation sent to recipient: %s\n", recipientID)

	return nil
}

// SendConnectionRequestNotification sends a notification to the recipient about a new connection request.
func (ns *NotificationServiceImpl) SendConnectionRequestNotification(senderID, recipientID uuid.UUID) error {
	message := fmt.Sprintf("You have a new connection request from user %s.", senderID)
	ns.SendNotification(recipientID, message, "ConnectionRequest", "")

	return nil
}

// DeleteNotification deletes a notification for a specific recipient.
func (ns *NotificationServiceImpl) DeleteNotification(recipientID, notificationID uuid.UUID) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Delete the notification from the database using the DBHandler
	err := ns.dbHandler.DeleteNotification(recipientID, notificationID)
	if err != nil {
		// Handle the error if deleting from the database fails
		return err
	}
	// Find the notification in the in-memory slice
	// var foundIndex = -1
	// for i, notification := range ns.notifications {
	// 	if notification.RecipientID == recipientID && notification.NotificationID == notificationID {
	// 		foundIndex = i
	// 		break
	// 	}
	// }

	// If the notification is found in the in-memory slice, remove it
	// if foundIndex != -1 {
	// 	ns.notifications = append(ns.notifications[:foundIndex], ns.notifications[foundIndex+1:]...)
	// } else {
	// 	// If the notification is not found, return an error.
	// 	return fmt.Errorf("notification not found for recipient: %s, notificationID: %s", recipientID, notificationID)
	// }

	return nil
}

// GetNotificationByID retrieves a notification by its ID for a specific recipient.
func (ns *NotificationServiceImpl) GetNotificationByID(recipientID, notificationID uuid.UUID) (*notifications.Notification, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// First, check if the notification is in the in-memory slice
	for _, notification := range ns.notifications {
		if notification.RecipientID == recipientID && notification.NotificationID == notificationID {
			return &notification, nil
		}
	}

	// If the notification is not found in the in-memory slice, fetch it from the database
	// Use the DBHandler to perform the database query
	notification, err := ns.dbHandler.GetNotificationByID(recipientID, notificationID)
	if err != nil {
		// Handle the error if fetching from the database fails
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return a more specific error if the notification is not found
			return nil, fmt.Errorf("notification not found for recipient: %s, notificationID: %s", recipientID, notificationID)
		}
		return nil, err
	}

	return notification, nil
}

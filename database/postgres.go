package database

import (
	// "errors"
	"errors"
	"fmt"
	"log"
	"os"

	// "github.com/google/uuid"
	"github.com/RohitKMishra/IamverseDemo/models"
	"github.com/RohitKMishra/IamverseDemo/notifications.go"
	"github.com/google/uuid"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB represents a Database instance
var DB *gorm.DB

// DBHandlerImpl is an implementation of the DBHandler interface.
type DBHandlerImpl struct {
	DB *gorm.DB
	// Add any other required fields or configurations
}

// SaveNotification saves a notification in the database.
func (h *DBHandlerImpl) SaveNotification(notification *notifications.Notification) error {
	if h.DB == nil {
		return errors.New("DB instance is nil")
	}

	if notification == nil {
		return errors.New("notification is nil")
	}

	// Ensure the notification ID is set (assuming it's a required field)
	if notification.NotificationID == uuid.Nil {
		return errors.New("notification ID is not set")
	}

	result := h.DB.Create(notification)
	if result.Error != nil {
		// Print the notification details for debugging
		fmt.Printf("Failed to create notification: %+v\n", notification)

		// Handle the error and return with additional context
		return fmt.Errorf("failed to save notification: %w", result.Error)
	}

	return nil
}

// DeleteNotification deletes a notification from the database.
func (h *DBHandlerImpl) DeleteNotification(recipientID, notificationID uuid.UUID) error {
	fmt.Println("inside delte notification database file")
	// Implement logic to delete the notification from the database
	err := h.DB.Where("recipient_id = ? AND notification_id = ?", recipientID, notificationID).Delete(&notifications.Notification{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete notification: %w", err)
	}

	return err
}

// GetNotificationByID retrieves a notification by its ID for a specific recipient.
func (h *DBHandlerImpl) GetNotificationByID(recipientID, notificationID uuid.UUID) (*notifications.Notification, error) {
	// Implement logic to fetch the notification by ID from the database
	// Example using GORM:
	var notification notifications.Notification
	err := h.DB.Where("recipient_id = ? AND notification_id = ?", recipientID, notificationID).First(&notification).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get notification by ID: %w", err)
	}

	return &notification, nil
}

// ConnectToDB connects the server with database
func ConnectToDB() error {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading env file \n", err)
	}

	// postgress database connection string
	// dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Kolkata",
	// 	os.Getenv("PSQL_HOST"), os.Getenv("PSQL_USER"), os.Getenv("PSQL_PASS"), os.Getenv("PSQL_DBNAME"), os.Getenv("PSQL_PORT"))

	db_URL := os.Getenv("PSQL_URL")

	fmt.Printf("DB_URL: %s\n", db_URL) // Print the database URL
	log.Print("Connecting to PostgreSQL DB...")
	// Open a connection to the PostgreSQL database using GORM.
	DB, err = gorm.Open(postgres.Open(db_URL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		log.Fatal("Failed to connect to database. \n", err)
		fmt.Println("Error:", err.Error())
		os.Exit(2)
	}
	log.Println("connected")
	DB = DB.Debug()
	dbHandler := &DBHandlerImpl{
		DB: DB,
	}
	fmt.Println("db handler", dbHandler)
	// Register model types
	models := []interface{}{
		&models.User{},
		&models.BasicInfo{},
		&models.Claims{},
		&models.Post{},
		&models.About{},
		&models.Address{},
		&models.Certifications{},
		&models.Education{},
		&models.Experience{},
		// &models.Hashtag{},
		// &models.Headline{},
		&models.Comment{},
		&models.Like{},
		&models.DemographicInfo{},
		&models.Course{},
		&models.Project{},
		&models.Skill{},
		&models.Media{},
		&models.Language{},
		// &models.HonorAward{},
		&models.Follower{},
		&models.Following{},
		// &models.CareerBreak{},
		// &models.VolunteerExperience{},
		// &models.Publication{},
		// &models.Patent{},
		// &models.TestScore{},
		// &models.Organization{},
		// &models.Cause{},
		// &models.CauseResponse{},
		// &models.Recommendation{},
		// &models.FeaturedSection{},
		// &models.FeaturedItem{},
		// &notifications.Notification{},
		// &models.Group{},
		// &models.GroupMember{},
		// &models.GroupPost{},
		// &models.GroupPostLike{},
		// &models.GroupPostComment{},
		// &models.GroupPostCommentReply{},
	}

	log.Print("Running the migrations...")
	err = DB.AutoMigrate(models...)
	if err != nil {
		log.Fatal("Error migrating models", err.Error())
	}

	// printAllEnvironmentVariables()

	return nil
}

// func CreateUserConnection(userID, connectedUserID uuid.UUID) error {
// 	connection := models.UserConnection{
// 		UserID:          userID,
// 		ConnectedUserID: connectedUserID,
// 		// Add other fields as needed
// 	}

// 	result := DB.Create(&connection)
// 	return result.Error
// }

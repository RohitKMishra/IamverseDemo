package controllers

// import (
// 	"errors"
// 	"fmt"
// 	"log"

// 	"github.com/gofiber/fiber/v2"
// 	"github.com/google/uuid"
// 	"github.com/nyshnt/codeapto-backend-go/database"
// 	db "github.com/nyshnt/codeapto-backend-go/database"
// 	"github.com/nyshnt/codeapto-backend-go/models"
// 	"gorm.io/gorm"
// )

// type UserDetails struct {
// 	ID        uuid.UUID `json:"id"`
// 	FirstName string    `json:"firstname"`
// 	LastName  string    `json:"lastname"`
// 	Url       string    `json:"url"`
// 	Picture   string    `json:"picture"`
// 	Banner    string    `json:"banner"`
// }

// type ConnectionDetails struct {
// 	User   UserDetails `json:"user"`
// 	Friend UserDetails `json:"friend"`
// 	Status string      `json:"status"`
// }

// func SendConnectionRequest(userID, friendID uuid.UUID, notificationService *services.NotificationServiceImpl) error {
// 	// Check if a pending connection request already exists
// 	var existingRequest models.Connection
// 	result := db.DB.Where("user_id = ? AND friend_id = ? AND status = 'Pending'", userID, friendID).First(&existingRequest)

// 	if result.Error == nil {
// 		log.Printf("Connection request already pending between %s and %s", userID, friendID)
// 		return errors.New("Connection request already pending")
// 	} else if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 		log.Printf("Error checking existing connection request: %v", result.Error)
// 		return result.Error
// 	}

// 	// Check if users are already connected
// 	var existingConnection models.Connection
// 	result = db.DB.Where("(user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?) AND status = 'Connected'", userID, friendID, friendID, userID).First(&existingConnection)

// 	if result.Error == nil {
// 		log.Printf("Users %s and %s are already connected", userID, friendID)
// 		return errors.New("Users are already connected")
// 	} else if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 		log.Printf("Error checking existing connection: %v", result.Error)
// 		return result.Error
// 	}

// 	// Create a new connection request
// 	connection := models.Connection{
// 		UserID:   userID,
// 		FriendID: friendID,
// 		Status:   "Pending",
// 	}

// 	// Store the connection request in the database
// 	if err := db.DB.Create(&connection).Error; err != nil {
// 		log.Printf("Error storing connection request in PostgreSQL: %v", err)
// 		return err
// 	}

// 	// Send notification to the friend about the new connection request
// 	notificationMessage := fmt.Sprintf("You have a new connection request from user %s.", userID)
// 	notificationService.SendNotification(friendID, notificationMessage, "connection_request", "")

// 	return nil
// }

// RespondToConnectionRequest handles responding to a connection request.
// func RespondToConnectionRequest(userID, friendID uuid.UUID, response string, notificationService *services.NotificationServiceImpl) error {
// 	// Validate the response (assuming it can be "Accepted" or "Rejected").
// 	if response != "Accepted" && response != "Rejected" {
// 		return fmt.Errorf("invalid response: %s", response)
// 	}

// 	err := db.DB.
// 		Where("user_id = ? AND friend_id = ? AND status = ?", userID, friendID, "Pending").
// 		Updates(models.Connection{Status: response}).
// 		Error
// 	if err != nil {
// 		log.Printf("Error updating connection request status in PostgreSQL: %v", err)
// 		return err
// 	}

// 	// Send notification to the user who initiated the connection request.
// 	var notificationMessage string
// 	if response == "Accepted" {
// 		notificationMessage = fmt.Sprintf("Your connection request to user %s has been accepted.", friendID)
// 	} else {
// 		notificationMessage = fmt.Sprintf("Your connection request to user %s has been rejected.", friendID)
// 	}

// 	notificationService.SendNotification(userID, notificationMessage, "connection_request_response", "")

// 	return nil
// }

// func GetUserConnections(userID uuid.UUID) ([]ConnectionDetails, error) {
// 	var connections []models.Connection
// 	if err := db.DB.Where("user_id = ? OR friend_id = ?", userID, userID).Find(&connections).Error; err != nil {
// 		log.Printf("Error fetching user connections from PostgreSQL: %v", err)
// 		return nil, err
// 	}

// 	var connectionDetails []ConnectionDetails
// 	for _, conn := range connections {
// 		user, err := GetUserDetails(conn.UserID)
// 		if err != nil {
// 			return nil, err
// 		}

// 		friend, err := GetUserDetails(conn.FriendID)
// 		if err != nil {
// 			return nil, err
// 		}

// 		connectionDetails = append(connectionDetails, ConnectionDetails{
// 			User:   user,
// 			Friend: friend,
// 			Status: conn.Status,
// 		})
// 	}

// 	return connectionDetails, nil
// }

// func GetUserDetails(userID uuid.UUID) (UserDetails, error) {
// 	var user models.User
// 	if err := db.DB.Where("uuid = ?", userID).First(&user).Error; err != nil {
// 		log.Printf("Error fetching user details from PostgreSQL: %v", err)
// 		return UserDetails{}, err
// 	}

// 	return UserDetails{
// 		ID:        user.UUID,
// 		FirstName: user.Firstname,
// 		LastName:  user.Lastname,
// 		Url:       user.Url,
// 		Picture:   user.Picture,
// 		Banner:    user.Banner,
// 	}, nil
// }

// func RemoveConnectedUser(userID, connectedUserID uuid.UUID) error {
// 	// Check if users are connected before attempting removal
// 	var existingConnection models.Connection
// 	result := db.DB.
// 		Where("(user_id = ? AND friend_id = ? AND status = 'Accepted') OR (user_id = ? AND friend_id = ? AND status = 'Accepted')",
// 			userID, connectedUserID, connectedUserID, userID).
// 		First(&existingConnection)

// 	if result.Error != nil {
// 		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 			log.Printf("Users %s and %s are not connected", userID, connectedUserID)
// 			return errors.New("users are not connected")
// 		}
// 		log.Printf("Error checking existing connection: %v", result.Error)
// 		return result.Error
// 	}

// 	return db.DB.Where("(user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", userID, connectedUserID, connectedUserID, userID).
// 		Delete(&models.Connection{}).Error
// }

// SendConnectionRequestHandler handles the API endpoint to send a connection request.
// func SendConnectionRequestHandler(c *fiber.Ctx) error {
// 	// Parse user IDs from the request
// 	userIDstr := c.Params("userID")
// 	userID, err := uuid.Parse(userIDstr)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
// 	}
// 	friendIDstr := c.Params("friendID")
// 	friendID, err := uuid.Parse(friendIDstr)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid friend ID"})
// 	}
// 	// Perform validation on user IDs
// 	dbHandler := &database.DBHandlerImpl{}

// 	notificationService := services.NewNotificationService(dbHandler)

// 	// Call the function to send a connection request
// 	if err := SendConnectionRequest((userID), (friendID), notificationService); err != nil {
// 		// Handle the error and return a proper response
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	// Return a success response
// 	return c.JSON(fiber.Map{"message": "Connection request sent successfully"})
// }

// RespondToConnectionRequestHandler handles the API endpoint to accept or reject a connection request.
// func RespondToConnectionRequestHandler(c *fiber.Ctx) error {
// 	// Parse user IDs and status from the request
// 	userIDstr := c.Params("userID")
// 	userID, err := uuid.Parse(userIDstr)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
// 	}
// 	friendIDstr := c.Params("friendID")
// 	friendID, err := uuid.Parse(friendIDstr)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
// 	}
// 	status := c.Params("status")

// 	// Perform validation on user IDs and status
// 	dbHandler := &database.DBHandlerImpl{}

// 	notificationService := services.NewNotificationService(dbHandler)
// 	// Call the function to respond to a connection request
// 	if err := RespondToConnectionRequest((userID), (friendID), status, notificationService); err != nil {
// 		// Handle the error and return a proper response
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error",
// 			"error msg": err.Error()})
// 	}

// 	// Return a success response
// 	return c.JSON(fiber.Map{"message": "Connection request responded successfully"})
// }

// GetUserConnectionsHandler handles the API endpoint to get a user's connections.
// func GetUserConnectionsHandler(c *fiber.Ctx) error {

// 	// Parse user ID from the request
// 	userID := c.Params("userID")
// 	// Call the function to get a user's connections
// 	connections, err := GetUserConnections(uuid.MustParse(userID))
// 	if err != nil {
// 		// Handle the error and return a proper response
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	// Return the list of connections as a JSON response
// 	return c.JSON(fiber.Map{"connections": connections})
// }

// func RemoveConnectedUserHandler(c *fiber.Ctx) error {
// 	ID := c.Locals("id").(string)
// 	userID, err := StringToUUID(ID)
// 	if err != nil {
// 		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
// 	}

// 	connectedUserID, err := uuid.Parse(c.Params("connectedUserID"))
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid connectedUserID"})
// 	}

// 	if err := RemoveConnectedUser(userID, connectedUserID); err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove connected user"})
// 	}

// 	return c.JSON(fiber.Map{"message": "Connected user removed successfully"})
// }

package adminroutes

import (
	// db is an alias for package codeapto-backend/database

	"github.com/gofiber/fiber/v2"
	"github.com/nyshnt/codeapto-backend-go/controllers"
	"github.com/nyshnt/codeapto-backend-go/util"
)

// SetupUserRoutes func sets up all the user routes
func SetupAdminRoutes(ADMIN fiber.Router) {
	ADMIN.Post("/signup", controllers.CreateUser)              // Sign Up a user
	ADMIN.Post("/signin", controllers.LoginUser)               // Sign In a user
	ADMIN.Get("/get-access-token", controllers.GetAccessToken) // returns a new access_token

	// privUser handles all the private user routes that requires authentication
	privUser := ADMIN.Group("/private")
	privUser.Use(util.SecureAuth()) // middleware to secure all routes for this group
	// privUser.Get("/user", controllers.GetUserData)
}

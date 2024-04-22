package router

import (
	"github.com/gofiber/fiber/v2"

	adminroutes "github.com/RohitKMishra/IamverseDemo/routes/admin"
	userroutes "github.com/RohitKMishra/IamverseDemo/routes/users"
)

// handler (controller) function of the route
func hello(c *fiber.Ctx) error {
	return c.SendString("Hello World!")
}

// USER handles all the user routes
var USER, ADMIN fiber.Router

// SetupRoutes setups all the Routes
func SetupRoutes(app *fiber.App) {
	api := app.Group("/v1")

	api.Get("/", hello)
	USER = api.Group("/user")
	ADMIN = api.Group("/admin")
	userroutes.SetupUserRoutes(USER)
	adminroutes.SetupAdminRoutes(ADMIN)
}

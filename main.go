package main

import (
	"log"
	"os"
	"strconv"
	// "strings"
	"time"

	router "github.com/RohitKMishra/IamverseDemo/routes"

	"github.com/RohitKMishra/IamverseDemo/database"
	"github.com/RohitKMishra/IamverseDemo/util"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	// "github.com/gofiber/fiber/v2/middleware/cors"
)

// CreateServer creates a new Fiber instance
func CreateServer() *fiber.App {
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization", // Include Authorization header
	}))
	return app
}

// func loadEnvFile(environment string) error {
// 	var envFile string
// 	if environment == "development" {
// 		envFile = ".env.prod"
// 	} else {
// 		envFile = ".env"
// 	}

// 	return godotenv.Load(envFile)
// }

func loadEnvFile(environment string) error {
	var envFile string
	if environment == "production" {
		envFile = ".env.prod"
	} else {
		envFile = ".env"
	}

	return godotenv.Load(envFile)
}

func DeleteOldNotificationsWrapper() {
	err := util.DeleteOldNotifications()
	if err != nil {
		log.Println("Error deleting old notifications:", err)
	}
}

// Define a helper function to check if a string is in a slice
func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func main() {

	c := cron.New()

	// Schedule the DeleteOldNotifications function to run every day at 2:00 AM
	_, err := c.AddFunc("0 11 * * *", DeleteOldNotificationsWrapper)
	if err != nil {
		log.Fatal("Error adding cron job:", err)
	}

	// Start the cron scheduler
	c.Start()
	// Load environment variables from the appropriate file
	err = loadEnvFile("production")
	if err != nil {
		log.Fatal("Failed to load environment variable. \n", err)
		os.Exit(2)
	}

	// Connect to Postgres
	database.ConnectToDB()
	// Connect to Redis

	app := CreateServer()

	router.SetupRoutes(app)

	started := time.Now()

	// Helath check function
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"started": started,
			"uptime": strconv.FormatInt(time.Now().Unix()-started.Unix(), 10) + " sec"})
	})

	// 404 Handler
	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404) // => 404 "Not Found"
	})

	log.Fatal(app.Listen(":3003"))

}

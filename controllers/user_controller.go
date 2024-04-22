package controllers

import (
	// "errors"
	"os"
	// "regexp"
	"strings"

	"math/rand"
	"time"

	db "github.com/RohitKMishra/IamverseDemo/database"
	"github.com/RohitKMishra/IamverseDemo/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	// "github.com/nyshnt/codeapto-backend-go/notifications"
	// "github.com/nyshnt/codeapto-backend-go/services"
	"gorm.io/gorm"

	"fmt"

	"github.com/RohitKMishra/IamverseDemo/util"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte(os.Getenv("PRIV_KEY"))

type User struct {
	UUID        string `json:"uuid"`
	FirstName   string `json:"firstname"`
	LastName    string `json:"lastname"`
	Email       string `json:"email"`
	CountryCode string `json:"countrycode"`
	Phone       string `json:"phone"`
	DOB         string `json:"dob"`
}
type UserSocialLogin struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Picture   string `json:"picture"`
}

func StringToUUID(str string) (uuid.UUID, error) {
	u, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, err
	}
	return u, nil
}

func generateRandomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := make([]byte, n)
	for i := range result {
		result[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(result)
}

func getUserIDByUsername(username string) (uuid.UUID, error) {
	var user models.User
	if err := db.DB.Where("url = ?", username).First(&user).Error; err != nil {
		return uuid.Nil, err
	}

	return user.UUID, nil
}

func isUsernameTaken(username string) bool {
	var user User
	result := db.DB.Where("url = ?", username).First(&user)
	return result.Error == nil // If there is no error, the username is taken
}

func CreateUser(c *fiber.Ctx) error {
	u := new(models.User)

	if err := c.BodyParser(u); err != nil {
		return c.JSON(fiber.Map{
			"error":   true,
			"input":   "Please review your input",
			"err msg": err,
		})
	}

	// Validate if the email, username, and password are in the correct format
	errors := util.ValidateRegister(u)
	if errors.Err {
		return c.JSON(errors)
	}

	// Check if the user with the same email already exists
	existingUser := new(models.User)
	if result := db.DB.Where(" emails @> ?", pq.Array(u.Emails)).First(&existingUser); result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// User with this email doesn't exist, proceed with registration
			u.Base = models.Base{UUID: uuid.New()}
			u.Url = strings.ToLower(u.Firstname + u.Lastname + generateRandomString(6))
			// Hash the password before storing in the database
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
			}
			u.Password = string(hashedPassword)
			if u.Picture == "" {
				u.Picture = "https://indineers1.s3.ap-south-1.amazonaws.com/dummy_img_user.jpeg"
			}

			if u.Banner == "" {
				u.Banner = "https://indineers1.s3.ap-south-1.amazonaws.com/maple-1079235_1280.jpeg"
			}

			if err := db.DB.Create(&u).Error; err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
			}
			fmt.Println("userid ", u.UUID)

			basicInfo := new(models.BasicInfo)
			basicInfo.BasicUserID = u.UUID
			basicInfo.BasicInfoID = uuid.New()
			basicInfo.Firstname = u.Firstname
			basicInfo.Lastname = u.Lastname
			basicInfo.City = u.City
			basicInfo.Country = u.Country
			if err := db.DB.Create(&basicInfo).Error; err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
			}

			// setting up the authorization cookies
			accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
			accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
			c.Cookie(accessCookie)
			c.Cookie(refreshCookie)

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			})
		} else {
			// Database error
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
		}
	} else {
		// User with the same email already exists, return a conflict error
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   true,
			"message": "User with this email already exists",
		})
	}
}

func SocialLogin(c *fiber.Ctx) error {
	// Parse the request body into a User struct
	var su models.User
	if err := c.BodyParser(&su); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
			"details": err.Error(),
		})
	}
	// Check if the email is empty
	for _, email := range su.Emails {
		if email == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Email cannot be empty",
			})
		}
	}
	// Check if a user with the provided email exists
	var existingUser models.User
	result := db.DB.Where("?", pq.Array(su.Emails)).First(&existingUser)

	if result.Error == gorm.ErrRecordNotFound {
		// Email is not in the database, proceed with registration
		su.Url = strings.ToLower(su.Firstname + su.Lastname + generateRandomString(6))
		su.UUID = uuid.New()
		u := models.User{
			Firstname: su.Firstname,
			Lastname:  su.Lastname,
			Emails:    su.Emails,
			Picture:   su.Picture,
			Url:       su.Url,
			// Other fields you may want to initialize
		}
		if u.Picture == "" {
			u.Picture = "https://indineers1.s3.ap-south-1.amazonaws.com/dummy_img_user.jpeg"
		}

		if u.Banner == "" {
			u.Banner = "https://codeapto.s3.ap-south-1.amazonaws.com/images.png"
		}
		// Create the user
		if err := db.DB.Create(&u).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Create basic info for the user
		basicInfo := models.BasicInfo{
			BasicInfoID: uuid.New(),
			BasicUserID: u.UUID,
			Firstname:   u.Firstname,
			Lastname:    u.Lastname,
		}

		if err := db.DB.Create(&basicInfo).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Setting up the authorization cookies
		accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
		accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
		c.Cookie(accessCookie)
		c.Cookie(refreshCookie)

		// Set the user ID in the context
		c.Locals("id", u.UUID.String())

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	} else if result.Error != nil {
		// Database error
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": result.Error.Error(),
		})
	}

	// User exists, send tokens
	accessToken, refreshToken := util.GenerateTokens(existingUser.UUID.String())
	accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	// Set the user ID in the context
	c.Locals("id", existingUser.UUID.String())

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// LoginUser route logins a user in the app validate input and password
// func LoginUser(c *fiber.Ctx) error {
// 	type LoginInput struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}

// 	input := new(LoginInput)

// 	if err := c.BodyParser(input); err != nil {
// 		return c.JSON(fiber.Map{"error": true, "input": "Please review your input"})
// 	}

// 	// Validate the email format
// 	validationResult := util.ValidateLoginInput(input.Email)
// 	if !validationResult.Valid {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": validationResult.Message,
// 		})
// 	}

// 	// Check if a user exists
// 	u := new(models.User)
// 	if res := db.DB.Where(
// 		&models.User{Email: input.Email},
// 	).First(&u); res.RowsAffected <= 0 {
// 		return c.JSON(fiber.Map{"error": true, "general": "Invalid Credentials."})
// 	}

// 	// Comparing the password with the hash
// 	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
// 		return c.JSON(fiber.Map{"error": true, "general": "Invalid Credentials."})
// 	}

// 	// Setting up the authorization cookies
// 	accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
// 	accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
// 	c.Cookie(accessCookie)
// 	c.Cookie(refreshCookie)

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	})
// }

// LoginUser handler
func LoginUser(c *fiber.Ctx) error {
	type LoginInput struct {
		Email    pq.StringArray `json:"email"`
		Password string         `json:"password"`
	}

	input := new(LoginInput)

	if err := c.BodyParser(input); err != nil {
		return c.JSON(fiber.Map{"error": true, "input": "Please review your input"})
	}

	fmt.Println("input data ", input)
	// Validate the email format
	for _, email := range input.Email {
		validationResult := util.ValidateLoginInput(email)
		if !validationResult.Valid {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": validationResult.Message,
			})
		}
	}
	// Check if a user exists
	u := new(models.User)
	if res := db.DB.Where(
		"emails && ?",
		pq.Array(input.Email),
	).First(&u); res.RowsAffected <= 0 {
		return c.JSON(fiber.Map{"error": true, "general": "Invalid Credentials."})
	}

	// Comparing the password with the hash
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
		return c.JSON(fiber.Map{"error": true, "general": "Invalid Credentials."})
	}

	// Setting up the authorization cookies
	accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
	accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// LogoutUser revokes the user's authentication tokens (e.g., access and refresh tokens)
func LogoutUser(c *fiber.Ctx) error {

	userUUID := c.Locals("id")

	if userUUID == "" {
		// Handle the case where the user is not authenticated.
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not authenticated"})
	}

	// Clear the user's authentication tokens from the client (browser) by setting empty or expired cookies.
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Expire the cookie in the past
		HTTPOnly: true,
	})
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Expire the cookie in the past
		HTTPOnly: true,
	})

	// Respond with a successful logout message
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Logged out successfully"})
}

func UserViewFnLnPhExpAll(c *fiber.Ctx) error {
	type NewUser struct {
		User_ID     uuid.UUID `json:"user_id"`
		Firstname   string    `json:"firstname"`
		Lastname    string    `json:"lastname"`
		Picture     string    `json:"picture"`
		Designation string    `json:"designation"`
		Url         string    `json:"url"`
		Verified    bool      `json:"verified"`
	}
	u := []models.User{}
	if res := db.DB.Find(&u); res.RowsAffected <= 0 {
		return c.JSON(fiber.Map{"error": true, "general": "Cannot find the User"})
	}

	// New array to store formatted data
	var newUsers []NewUser

	// Mapping users struct to NewUser struct
	for _, user := range u {
		newMappedUser := NewUser{
			User_ID:     user.UUID,
			Firstname:   user.Firstname,
			Lastname:    user.Lastname,
			Picture:     user.Picture,
			Designation: user.Role,
			Url:         user.Url,
			Verified:    user.Verified, // Include the Verified field
		}
		newUsers = append(newUsers, newMappedUser)
	}
	return c.JSON(newUsers)
}

// GetUserByID retrieves a user by ID
func GetUserByID(userID uuid.UUID) *models.User {

	user := new(models.User)
	if result := db.DB.Where("uuid = ?", userID).First(&user); result.Error != nil {
		return nil
	}

	return user
}

func GetUserDetailsByID(c *fiber.Ctx) error {
	id := c.Params("id")

	users := new(models.User)
	if result := db.DB.Where("uuid = ?", id).Find(&users); result.RowsAffected <= 0 {
		return c.JSON(fiber.Map{"error": result.Error, "general": "Cannot find User"})
	}

	return c.JSON(fiber.Map{"users": users})
}

// GetAccessToken generates and sends a new access token iff there is a valid refresh token
func GetAccessToken(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")

	refreshClaims := new(models.Claims)
	token, _ := jwt.ParseWithClaims(refreshToken, refreshClaims,
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if res := db.DB.Where(
		"expires_at = ? AND issued_at = ? AND issuer = ?",
		refreshClaims.ExpiresAt, refreshClaims.IssuedAt, refreshClaims.Issuer,
	).First(&models.Claims{}); res.RowsAffected <= 0 {
		// no such refresh token exist in the database
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	if token.Valid {
		if refreshClaims.ExpiresAt < time.Now().Unix() {
			// refresh token is expired
			c.ClearCookie("access_token", "refresh_token")
			return c.SendStatus(fiber.StatusForbidden)
		}
	} else {
		// malformed refresh token
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	_, accessToken := util.GenerateAccessClaims(refreshClaims.Issuer)

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.JSON(fiber.Map{"access_token": accessToken})
}

// // UpdateUserData updates the user details
// func UpdateUserData(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	// id1, err := StringToUUID(id)
// 	// if err != nil {
// 	// 	return err
// 	// }

// 	user := new(models.User)
// 	if err := db.DB.Where("uuid = ?", id).Find(&user).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "failed to fetch post details",
// 			"error": err.Error(),
// 		})
// 	}
// 	fmt.Println("user ", user)
// 	var userData struct {
// 		Firstname    *string         `json:"firstname"`
// 		Lastname     *string         `json:"lastname"`
// 		Url          *string         `json:"url"`
// 		Countrycode  *string         `json:"countrycode"`
// 		Phone        *pq.StringArray `json:"phone"`
// 		Dob          *string         `json:"dob"`
// 		Picture      *string         `json:"picture"`
// 		Address      *string         `json:"address"`
// 		Banner       *string         `json:"banner"`
// 		Country      *string         `json:"country"`
// 		City         *string         `json:"city"`
// 		State        *string         `json:"state"`
// 		PortfolioUrl *string         `json:"portfolio_url"`
// 	}

// 	if err := c.BodyParser(&userData); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if userData.Firstname != nil {
// 		user.Firstname = *userData.Firstname
// 	}
// 	if userData.Lastname != nil {
// 		user.Lastname = *userData.Lastname
// 	}
// 	if userData.Countrycode != nil {
// 		user.Countrycode = *userData.Countrycode
// 	}
// 	if userData.Phone != nil {
// 		user.Phone = *userData.Phone
// 	}
// 	if userData.Dob != nil {
// 		user.Dob = *userData.Dob
// 	}
// 	if userData.Picture != nil {
// 		user.Picture = *userData.Picture
// 	}
// 	if userData.Country != nil {
// 		user.Country = *userData.Country
// 	}
// 	if userData.City != nil {
// 		user.City = *userData.City
// 	}
// 	if userData.State != nil {
// 		user.State = *userData.State
// 	}
// 	if userData.Banner != nil {
// 		user.Banner = *userData.Banner
// 	}
// 	if userData.Address != nil {
// 		user.State = *userData.Address
// 	}
// 	if userData.PortfolioUrl != nil {
// 		user.PortfolioUrl = *userData.PortfolioUrl
// 	}
// 	// user.Url = urlStringInLower
// 	if err := db.DB.Save(&user).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update user table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":      "user details updated sucessfully",
// 		"updated data": user,
// 	})
// }

// func URLExists(db *gorm.DB, url string) bool {
// 	var user models.User
// 	if err := db.Where("url = ?", url).First(&user).Error; err != nil {
// 		return false
// 	}
// 	return true
// }
// func GetAllUsers(c *fiber.Ctx) error {
// 	var u []models.User

// 	if result := db.DB.Find(&u); result.Error != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "users not found",
// 		})
// 	} else {
// 		return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 			"count": len(u),
// 			"users": u,
// 		})
// 	}
// }

// func UpdateUserUrl(c *fiber.Ctx) error {
// 	id := c.Locals("id")
// 	url := c.Params("url")

// 	// Check if the URL already exists in the database
// 	if URLExists(db.DB, url) {
// 		return c.JSON(fiber.Map{
// 			"error":   "URL already exists",
// 			"message": "URL already in use by another user",
// 		})
// 	}

// 	userFromDB := new(models.User)
// 	if result := db.DB.Where("uuid = ?", id).Find(&userFromDB); result.RowsAffected <= 0 {
// 		return c.JSON(fiber.Map{"error": result.Error, "general": "Cannot find User"})
// 	}

// 	// Update the user's URL
// 	userFromDB.Url = url

// 	if err := db.DB.Save(&userFromDB).Error; err != nil {
// 		return c.JSON(fiber.Map{"error": err.Error, "message": "Failed to update user URL"})
// 	}

// 	return c.JSON(fiber.Map{
// 		"message": "User URL updated successfully",
// 		"userUrl": url,
// 	})
// }

// // Get user data via url
// func GetUserByUrl(c *fiber.Ctx) error {
// 	url := c.Params("url")
// 	fmt.Println("url ", url)

// 	// Find the user based on the URL field
// 	var user models.User
// 	if err := db.DB.Where("url = ?", url).First(&user).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "User not found",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(user)
// }

// func DeleteUser(c *fiber.Ctx) error {
// 	return nil
// }

// func UpdateUserLocation(c *fiber.Ctx) error {
// 	id := c.Locals("id")

// 	type UserLocation struct {
// 		Country string `json:"country"`
// 		City    string `json:"city"`
// 		State   string `json:"state"`
// 	}

// 	userLocation := new(UserLocation)

// 	if err := c.BodyParser(userLocation); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": true,
// 			"input": "Please review your input",
// 		})
// 	}

// 	u := new(models.User)
// 	if res := db.DB.Where("uuid = ?", id).First(&u); res.RowsAffected <= 0 {
// 		return c.JSON(fiber.Map{"error": true, "message": "Invalid user"})
// 	}

// 	// Update user fields
// 	u.Country = userLocation.Country
// 	u.City = userLocation.City
// 	u.State = userLocation.State

// 	// Save the updated user
// 	result := db.DB.Save(&u)
// 	if result.Error != nil {
// 		return result.Error
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "user location updated sucessfully",
// 	})
// }

// func CreateBasicInfo(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	id1, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	basicInfo := new(models.BasicInfo)
// 	if err := c.BodyParser(basicInfo); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
// 	}

// 	basicInfo.BasicUserID = id1
// 	basicInfo.BasicInfoID = uuid.New()
// 	if err := db.DB.Create(&basicInfo).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(basicInfo)
// }

// func GetBasicInfo(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	id1, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	basicInfo := []models.BasicInfo{}
// 	if err := db.DB.Where("basic_user_id", id1).Find(&basicInfo).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to fetch education details",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(basicInfo)
// }

// func UpdateBasicInfo(c *fiber.Ctx) error {
// 	// id := c.Locals("id").(string)
// 	// id1, err := StringToUUID(id)
// 	// if err != nil {
// 	// 	return err
// 	// }
// 	basic_info_id := c.Params("id")

// 	var info models.BasicInfo
// 	if err := db.DB.Where("basic_info_id = ?", basic_info_id).Find(&info).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "failed to fetch basic info details",
// 			"error": err.Error(),
// 		})
// 	}
// 	fmt.Println("info ", info)
// 	var userInfo struct {
// 		UserID         uuid.UUID            `json:"user_id"`
// 		Firstname      *string              `json:"firstname"`
// 		Lastname       *string              `json:"lastname"`
// 		Education      *[]models.Education  `json:"education"`
// 		Position       *[]models.Experience `json:"position"`
// 		Industry       *string              `json:"industry"`
// 		AdditionalName *string              `json:"aditional_name"`
// 		Pronouns       *string              `json:"pronouns"`
// 		Headline       *string              `json:"headline"`
// 		City           *string              `json:"city"`
// 		Country        *string              `json:"country"`
// 	}

// 	if err := c.BodyParser(&userInfo); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if userInfo.Firstname != nil {
// 		info.Firstname = *userInfo.Firstname
// 	}
// 	if userInfo.Lastname != nil {
// 		info.Lastname = *userInfo.Lastname
// 	}
// 	if userInfo.AdditionalName != nil {
// 		info.AdditionalName = *userInfo.AdditionalName
// 	}
// 	if userInfo.Education != nil {
// 		info.Education = *userInfo.Education
// 	}
// 	if userInfo.Position != nil {
// 		info.Position = *userInfo.Position
// 	}
// 	if userInfo.Industry != nil {
// 		info.Industry = *userInfo.Industry
// 	}
// 	if userInfo.Pronouns != nil {
// 		info.Pronouns = *userInfo.Pronouns
// 	}
// 	if userInfo.Headline != nil {
// 		info.Headline = *userInfo.Headline
// 	}
// 	if userInfo.City != nil {
// 		info.City = *userInfo.City
// 	}
// 	if userInfo.Country != nil {
// 		info.Country = *userInfo.Country
// 	}
// 	fmt.Println("Basic info after update", &info)
// 	if err := db.DB.Save(&info).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update basic info table",
// 		})
// 	}
// 	// using basic info id fetch userID and update details

// 	var user models.BasicInfo
// 	if err := db.DB.Where("basic_user_id = ?", info.BasicUserID).First(&user).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
// 	}
// 	fmt.Println("User from db", user)
// 	// Update user details here

// 	var userData struct {
// 		Firstname *string `json:"firstname"`
// 		Lastname  *string `json:"lastname"`
// 		Country   *string `json:"country"`
// 		City      *string `json:"city"`
// 	}

// 	if userInfo.Firstname != nil {
// 		userData.Firstname = userInfo.Firstname
// 	}
// 	if userInfo.Lastname != nil {
// 		userData.Lastname = userInfo.Lastname
// 	}
// 	if userInfo.City != nil {
// 		userData.City = userInfo.City
// 	}
// 	if userInfo.Country != nil {
// 		userData.Country = userInfo.Country
// 	}

// 	if err := db.DB.Model(&models.User{}).Where("uuid = ?", info.BasicUserID).Updates(&userData).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update user details table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "user details updated sucessfully",
// 		"data":    info,
// 	})
// }

// func DeleteBasicInfo(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	if err := db.DB.Where("id = ?", id).Delete(&models.BasicInfo{}).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "BasicInfo deleted"})
// }

// func CreateDemographicInfo(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	id1, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	demoinfo := new(models.DemographicInfo)
// 	if err := c.BodyParser(&demoinfo); err != nil {
// 		return c.Status(400).JSON(fiber.Map{
// 			"error": "Invalid request data",
// 		})
// 	}

// 	demoinfo = &models.DemographicInfo{
// 		DemographicInfoUserId: id1,
// 		Disability:            demoinfo.Disability,
// 		Gender:                demoinfo.Gender,
// 	}
// 	result := db.DB.Create(&demoinfo)
// 	if result.Error != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to insert data in demographic info table",
// 		})
// 	}
// 	return c.Status(201).JSON(demoinfo)
// }

// func GetDemographicInfo(c *fiber.Ctx) error {
// 	// Extract the ID from the URL parameters
// 	id := c.Locals("id")

// 	demographic := []models.DemographicInfo{}
// 	if err := db.DB.Where("demographic_info_user_id", id).Find(&demographic).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to fetch demographic details",
// 		})
// 	}

// 	return c.Status(200).JSON(demographic)
// }

// func UpdateDemographicInfo(c *fiber.Ctx) error {
// 	demographic_info_user_id := c.Params("id")

// 	var demoInfo models.DemographicInfo
// 	if err := db.DB.Where("demographic_info_user_id = ?", demographic_info_user_id).Find(&demoInfo).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "failed to fetch demographic info details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var newDemographicInfo struct {
// 		Gender     *string `json:"gender"`
// 		Disability *string `json:"disability"`
// 	}
// 	fmt.Println("info ", demoInfo)

// 	if err := c.BodyParser(&newDemographicInfo); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if newDemographicInfo.Gender != nil {
// 		demoInfo.Gender = *newDemographicInfo.Gender
// 	}
// 	if newDemographicInfo.Disability != nil {
// 		demoInfo.Disability = *newDemographicInfo.Disability
// 	}

// 	fmt.Println("Basic info after update", &demoInfo)
// 	if err := db.DB.Save(&demoInfo).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update demographic info table",
// 		})
// 	}
// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":   "Demographic info updated successfully",
// 		"education": demoInfo,
// 	})
// }

// func DeleteDemographicInfo(c *fiber.Ctx) error {
// 	// Extract the ID from the URL parameters
// 	demographic_info_user_id := c.Params("id")

// 	if err := db.DB.Where("demographic_info_user_id = ? ", demographic_info_user_id).Delete(&models.DemographicInfo{}).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"message": "Demographic info deletion failed",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Demographic info deleted"})
// }

// // CreateCourse creates a new Course
// func CreateCourse(c *fiber.Ctx) error {

// 	id := c.Locals("id").(string)
// 	id1, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	course := new(models.Course)
// 	if err := c.BodyParser(&course); err != nil {
// 		return c.Status(400).JSON(fiber.Map{
// 			"error": "Invalid request data",
// 		})
// 	}

// 	course = &models.Course{
// 		CourseID:           uuid.New(),
// 		CourseUserID:       id1,
// 		CourseName:         course.CourseName,
// 		CourseNumber:       course.CourseNumber,
// 		AssociatedWith:     course.AssociatedWith,
// 		CourseStartMonth:   course.CourseStartMonth,
// 		CourseEndMonth:     course.CourseEndMonth,
// 		CourseStartYear:    course.CourseStartYear,
// 		CourseEndYear:      course.CourseEndYear,
// 		InstituteLogo:      course.InstituteLogo,
// 		CourseInstituteURL: course.CourseInstituteURL,
// 	}
// 	result := db.DB.Create(&course)
// 	if result.Error != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to insert data in demographic info table",
// 		})
// 	}
// 	return c.Status(201).JSON(course)
// }

// func GetCourse(c *fiber.Ctx) error {
// 	id := c.Locals("id")

// 	course := []models.Course{}
// 	if err := db.DB.Where("course_user_id", id).Find(&course).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to fetch demographic details",
// 		})
// 	}

// 	return c.Status(200).JSON(course)
// }

// func GetCoursesByUserID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	courses := []models.Course{}
// 	if result := db.DB.Where("course_user_id = ?", userID).Find(&courses); result.RowsAffected <= 0 {
// 		return c.JSON(fiber.Map{"error": result.Error, "general": "Cannot find User"})
// 	}

// 	return c.JSON(courses)
// }

// func UpdateCourse(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	course_id, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var course models.Course
// 	if err := db.DB.Where("course_id = ?", course_id).Find(&course).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "failed to fetch post details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var newCourse struct {
// 		CourseName         *string `json:"course_name"`
// 		CourseNumber       *string `json:"course_number"`
// 		AssociatedWith     *string `json:"associated_with"`
// 		CourseStartMonth   *string `json:"course_start_month"`
// 		CourseStartYear    *string `json:"course_start_year"`
// 		CourseEndMonth     *string `json:"course_end_month"`
// 		CourseEndYear      *string `json:"course_end_year"`
// 		InstituteLogo      *string `json:"institute_logo"`
// 		CourseInstituteURL *string `json:"course_institute_url"`
// 	}
// 	if err := c.BodyParser(&newCourse); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if newCourse.AssociatedWith != nil {
// 		course.AssociatedWith = *newCourse.AssociatedWith
// 	}
// 	if newCourse.CourseName != nil {
// 		course.CourseName = *newCourse.CourseName
// 	}
// 	if newCourse.CourseNumber != nil {
// 		course.CourseNumber = *newCourse.CourseNumber
// 	}
// 	if newCourse.CourseStartMonth != nil {
// 		course.CourseStartMonth = *newCourse.CourseStartMonth
// 	}
// 	if newCourse.CourseEndMonth != nil {
// 		course.CourseEndMonth = *newCourse.CourseEndMonth
// 	}
// 	if newCourse.CourseStartYear != nil {
// 		course.CourseStartYear = *newCourse.CourseStartYear
// 	}
// 	if newCourse.CourseEndYear != nil {
// 		course.CourseEndYear = *newCourse.CourseEndYear
// 	}
// 	if newCourse.InstituteLogo != nil {
// 		course.InstituteLogo = *newCourse.InstituteLogo
// 	}
// 	if newCourse.CourseInstituteURL != nil {
// 		course.CourseInstituteURL = *newCourse.CourseInstituteURL
// 	}
// 	fmt.Println("info ", course)

// 	if err := db.DB.Save(&course).Error; err != nil {
// 		return c.Status(500).JSON(fiber.Map{
// 			"error": "Failed to update course",
// 		})
// 	}

// 	return c.Status(200).JSON(fiber.Map{
// 		"message": "Course details updated sucessfully",
// 		"data":    course,
// 	})
// }

// func DeleteCourse(c *fiber.Ctx) error {
// 	id := c.Params("id")

// 	if err := db.DB.Delete(&models.Course{}, "course_id = ?", id).Error; err != nil {
// 		return c.Status(500).JSON(fiber.Map{
// 			"error": "Failed to delete course",
// 		})
// 	}

// 	return c.Status(204).JSON(fiber.Map{"message": "Course deleted"})
// }

// func CreateProject(c *fiber.Ctx) error {
// 	// Get the user ID from locals and convert it to a UUID
// 	userIDStr := c.Locals("id").(string)
// 	userID, err := StringToUUID(userIDStr)
// 	if err != nil {
// 		return err
// 	}

// 	// Parse the request body into a project model
// 	var requestBody struct {
// 		ProjectName        string `json:"project_name"`
// 		ProjectDescription string `json:"project_description"`
// 		ProjectURL         string `json:"project_url"`
// 		StartMonth         string `json:"start_month"`
// 		EndMonth           string `json:"end_month"`
// 		StartYear          string `json:"start_year"`
// 		EndYear            string `json:"end_year"`
// 		Skills             []struct {
// 			SkillName       string `json:"skill_name"`
// 			ExperienceLevel string `json:"experience_level"`
// 		} `json:"skills"`
// 		Media []struct {
// 			Link        string `json:"link"`
// 			UploadMedia string `json:"upload_media"`
// 		} `json:"media"`
// 		Contributors      string `json:"contributors"`
// 		AdditionalDetails string `json:"additional_details"`
// 	}

// 	if err := c.BodyParser(&requestBody); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error": "Invalid project data",
// 		})
// 	}
// 	// Create a new project
// 	project := models.Project{
// 		ProjectID:          uuid.New(),
// 		ProjectUserId:      userID,
// 		ProjectName:        requestBody.ProjectName,
// 		ProjectDescription: requestBody.ProjectDescription,
// 		ProjectURL:         requestBody.ProjectURL,
// 		StartMonth:         requestBody.StartMonth,
// 		EndMonth:           requestBody.EndMonth,
// 		StartYear:          requestBody.StartYear,
// 		EndYear:            requestBody.EndYear,
// 		Contributors:       requestBody.Contributors,
// 		AdditionalDetails:  requestBody.AdditionalDetails,
// 	}

// 	// Create skill instances
// 	skills := make([]models.Skill, 0)
// 	for _, skillData := range requestBody.Skills {
// 		skill := models.Skill{
// 			SkillID:     uuid.New(),
// 			Name:        skillData.SkillName,
// 			Proficiency: skillData.ExperienceLevel,
// 			UserID:      userID,
// 			// You may set other skill-related fields here
// 		}
// 		skills = append(skills, skill)
// 	}
// 	project.Skills = skills

// 	// Create media instances
// 	media := make([]models.Media, 0)
// 	for _, mediaData := range requestBody.Media {
// 		mediaInstance := models.Media{
// 			MediaID:     uuid.New(),
// 			Link:        mediaData.Link,
// 			UploadMedia: mediaData.UploadMedia,
// 			// You may set other media-related fields here
// 		}
// 		media = append(media, mediaInstance)
// 	}
// 	project.Media = media

// 	// Save the project and its associations in the database
// 	if err := db.DB.Create(&project).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to create the project",
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
// 		"message": "Project created successfully",
// 		"data":    project,
// 	})
// }

// func GetProjectByURL(c *fiber.Ctx) error {
// 	url := c.Params("url")
// 	fmt.Println("url ", url)
// 	// Find the user based on the URL field
// 	var project models.Project
// 	if err := db.DB.Preload("Skills").Preload("Media").Where("project_url = ?", url).First(&project).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "project not found",
// 		})
// 	}
// 	return c.Status(fiber.StatusOK).JSON(project)
// }

// func GetProject(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	projectID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	var project models.Project
// 	if err := db.DB.Preload("Skills").Preload("Media").First(&project, projectID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Project not found",
// 		})
// 	}

// 	return c.JSON(project)
// }

// func GetProjectsByUserID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	projects := []models.Project{}
// 	if result := db.DB.Where("project_user_id = ?", userID).Find(&projects); result.RowsAffected <= 0 {
// 		return c.JSON(fiber.Map{"error": result.Error, "general": "Cannot find User"})
// 	}

// 	return c.JSON(projects)
// }

// func UpdateProject(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	projectID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	var project models.Project
// 	if err := db.DB.First(&project, projectID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Project not found",
// 		})
// 	}

// 	newProjectData := new(models.Project)
// 	if err := c.BodyParser(newProjectData); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error": "Invalid project data",
// 		})
// 	}

// 	// Update only the provided fields
// 	if newProjectData.ProjectName != "" {
// 		project.ProjectName = newProjectData.ProjectName
// 	}
// 	if newProjectData.ProjectDescription != "" {
// 		project.ProjectDescription = newProjectData.ProjectDescription
// 	}
// 	if newProjectData.StartMonth != "" {
// 		project.StartMonth = newProjectData.StartMonth
// 	}
// 	if newProjectData.EndMonth != "" {
// 		project.EndMonth = newProjectData.EndMonth
// 	}
// 	if newProjectData.StartYear != "" {
// 		project.StartYear = newProjectData.StartYear
// 	}
// 	if newProjectData.EndYear != "" {
// 		project.EndYear = newProjectData.EndYear
// 	}
// 	if newProjectData.Skills != nil {
// 		project.Skills = newProjectData.Skills
// 	}
// 	if newProjectData.Media != nil {
// 		project.Media = newProjectData.Media
// 	}
// 	if newProjectData.Contributors != "" {
// 		project.Contributors = newProjectData.Contributors
// 	}
// 	if newProjectData.AdditionalDetails != "" {
// 		project.AdditionalDetails = newProjectData.AdditionalDetails
// 	}

// 	if err := db.DB.Save(&project).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update the project",
// 		})
// 	}

// 	return c.JSON(project)
// }

// func DeleteProject(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	projectID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	var project models.Project
// 	if err := db.DB.First(&project, projectID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Project not found",
// 		})
// 	}

// 	// Delete the project from the database
// 	if err := db.DB.Delete(&project).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the project",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Project deleted successfully",
// 	})
// }

// func CreateLanguage(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the request body into a Language struct
// 	var newLanguage models.Language
// 	if err := c.BodyParser(&newLanguage); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	// Create a new UUID for the language
// 	newLanguage.LanguageID = uuid.New()

// 	// Convert the userID to a UUID
// 	userIDUUID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid user ID",
// 		})
// 	}

// 	// Set the UserID field
// 	newLanguage.UserID = userIDUUID

// 	// Save the new language entry to the database
// 	if err := db.DB.Create(&newLanguage).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(newLanguage)
// }

// // Update an existing Language
// func UpdateLanguageByID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the Language ID from the request parameters
// 	languageID := c.Params("id")

// 	// Convert the language ID to a UUID
// 	languageIDUUID, err := uuid.Parse(languageID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid Language ID",
// 		})
// 	}

// 	// Check if the Language exists and belongs to the user
// 	var existingLanguage models.Language
// 	if err := db.DB.Where("language_id = ? AND user_id = ?", languageIDUUID, userID).First(&existingLanguage).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Language not found",
// 		})
// 	}

// 	// Parse the request body into a Language struct
// 	var updatedLanguage models.Language
// 	if err := c.BodyParser(&updatedLanguage); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Only update the fields that are provided
// 	if updatedLanguage.LanguageName != "" {
// 		existingLanguage.LanguageName = updatedLanguage.LanguageName
// 	}
// 	if updatedLanguage.LanguageProficiency != "" {
// 		existingLanguage.LanguageProficiency = updatedLanguage.LanguageProficiency
// 	}

// 	// Update the Language in the database
// 	if err := db.DB.Save(&existingLanguage).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":  "Language updated successfully",
// 		"language": existingLanguage,
// 	})
// }

// // Get all Languages for a user
// func GetLanguages(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Convert the userID to a UUID
// 	userIDUUID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid user ID",
// 		})
// 	}

// 	// Query the database for all Languages associated with the user
// 	var languages []models.Language
// 	if err := db.DB.Where("user_id = ?", userIDUUID).Find(&languages).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(languages)
// }

// func GetLanguageByID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	langID := c.Params("id")

// 	// Convert the userID to a UUID
// 	userIDUUID, err := uuid.Parse(langID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid user ID",
// 		})
// 	}

// 	// Query the database for all Languages associated with the user
// 	var languages models.Language
// 	if err := db.DB.Where("language_id = ?", userIDUUID).Find(&languages).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(languages)
// }

// func GetLanguageByUserID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Params("id")

// 	// Convert the userID to a UUID
// 	userIDUUID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid user ID",
// 		})
// 	}

// 	// Query the database for all Languages associated with the user
// 	var languages []models.Language
// 	if err := db.DB.Where("user_id = ?", userIDUUID).Find(&languages).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(languages)
// }

// // Delete a Language by ID
// func DeleteLanguage(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the Language ID from the request parameters
// 	languageID := c.Params("id")

// 	// Convert the language ID to a UUID
// 	languageIDUUID, err := uuid.Parse(languageID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid Language ID",
// 		})
// 	}

// 	// Check if the Language exists and belongs to the user
// 	var existingLanguage models.Language
// 	if err := db.DB.Where("language_id = ? AND user_id = ?", languageIDUUID, userID).First(&existingLanguage).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Language not found",
// 		})
// 	}

// 	// Delete the Language from the database
// 	if err := db.DB.Delete(&existingLanguage).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Language deleted successfully",
// 	})
// }
// func CreateCareerBreak(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	careerBreak := new(models.CareerBreak)

// 	if err := c.BodyParser(careerBreak); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	careerBreak = &models.CareerBreak{
// 		CareerBreakID:     uuid.New(),
// 		CareerBreakUserID: userID,
// 		StartMonth:        careerBreak.StartMonth,
// 		EndMonth:          careerBreak.EndMonth,
// 		StartYear:         careerBreak.StartYear,
// 		EndYear:           careerBreak.EndYear,
// 		Reason:            careerBreak.Reason,
// 		Description:       careerBreak.Description,
// 	}
// 	// Save the career break entry to the database.
// 	if err := db.DB.Create(careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(careerBreak)
// }

// // GetCareerBreak retrieves a career break entry by CareerBreakUserID.
// func GetCareerBreak(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id")

// 	// Query the database for the user's career break
// 	careerBreak := []models.CareerBreak{}
// 	if err := db.DB.Where("career_break_user_id = ?", userID).Find(&careerBreak).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Career break not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(careerBreak)
// }

// func GetCareerBreakByCBrkID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	career_break_id := c.Params("id")

// 	// Query the database for the user's career break
// 	var careerBreak models.CareerBreak
// 	if err := db.DB.Where("career_break_id = ?", career_break_id).First(&careerBreak).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Career break not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(careerBreak)
// }

// func UpdateCareerBreak(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var careerBreak models.CareerBreak
// 	if err := db.DB.Where("career_break_user_id = ?", userID).First(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch career break details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userCareerBreak struct {
// 		StartMonth  *string `json:"start_month"`
// 		EndMonth    *string `json:"end_month"`
// 		StartYear   *string `json:"start_year"`
// 		EndYear     *string `json:"end_year"`
// 		Reason      *string `json:"reason"`
// 		Description *string `json:"description"`
// 	}

// 	if err := c.BodyParser(&userCareerBreak); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing career break
// 	if userCareerBreak.StartMonth != nil {
// 		careerBreak.StartMonth = *userCareerBreak.StartMonth
// 	}
// 	if userCareerBreak.EndMonth != nil {
// 		careerBreak.EndMonth = *userCareerBreak.EndMonth
// 	}
// 	if userCareerBreak.StartYear != nil {
// 		careerBreak.StartYear = *userCareerBreak.StartYear
// 	}
// 	if userCareerBreak.EndYear != nil {
// 		careerBreak.EndYear = *userCareerBreak.EndYear
// 	}
// 	if userCareerBreak.Reason != nil {
// 		careerBreak.Reason = *userCareerBreak.Reason
// 	}
// 	if userCareerBreak.Description != nil {
// 		careerBreak.Description = *userCareerBreak.Description
// 	}

// 	// Update the career break in the database
// 	if err := db.DB.Save(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update career break table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":      "Career break updated successfully",
// 		"career_break": careerBreak,
// 	})
// }

// // UpdateCareerBreakByCBrkID
// func UpdateCareerBreakByCBrkID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var careerBreak models.CareerBreak
// 	if err := db.DB.Where("career_break_id = ?", userID).First(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch career break details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userCareerBreak struct {
// 		StartMonth  *string `json:"start_month"`
// 		EndMonth    *string `json:"end_month"`
// 		StartYear   *string `json:"start_year"`
// 		EndYear     *string `json:"end_year"`
// 		Reason      *string `json:"reason"`
// 		Description *string `json:"description"`
// 	}

// 	if err := c.BodyParser(&userCareerBreak); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing career break
// 	if userCareerBreak.StartMonth != nil {
// 		careerBreak.StartMonth = *userCareerBreak.StartMonth
// 	}
// 	if userCareerBreak.EndMonth != nil {
// 		careerBreak.EndMonth = *userCareerBreak.EndMonth
// 	}
// 	if userCareerBreak.StartYear != nil {
// 		careerBreak.StartYear = *userCareerBreak.StartYear
// 	}
// 	if userCareerBreak.EndYear != nil {
// 		careerBreak.EndYear = *userCareerBreak.EndYear
// 	}
// 	if userCareerBreak.Reason != nil {
// 		careerBreak.Reason = *userCareerBreak.Reason
// 	}
// 	if userCareerBreak.Description != nil {
// 		careerBreak.Description = *userCareerBreak.Description
// 	}

// 	// Update the career break in the database
// 	if err := db.DB.Save(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update career break table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":      "Career break updated successfully",
// 		"career_break": careerBreak,
// 	})
// }

// func DeleteCareerBreakByCareerBreakID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	careerBreakID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var careerBreak models.CareerBreak
// 	if err := db.DB.First(&careerBreak, careerBreakID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Career break not found",
// 		})
// 	}

// 	// Delete the career break from the database
// 	if err := db.DB.Delete(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the career break",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Career break deleted successfully",
// 	})
// }

// func DeleteCareerBreakByUserID(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	careerBreakUserID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var careerBreak models.CareerBreak
// 	if err := db.DB.First(&careerBreak, careerBreakUserID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Career break not found",
// 		})
// 	}

// 	// Delete the career break from the database
// 	if err := db.DB.Delete(&careerBreak).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the career break",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Career break deleted successfully",
// 	})
// }

// func CreateVolunteerExperience(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	volunteerExperience := new(models.VolunteerExperience)

// 	if err := c.BodyParser(volunteerExperience); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	volunteerExperience = &models.VolunteerExperience{
// 		VolunteerExperienceID: uuid.New(),
// 		VolunteerUserID:       userID,
// 		StartMonth:            volunteerExperience.StartMonth,
// 		EndMonth:              volunteerExperience.EndMonth,
// 		StartYear:             volunteerExperience.StartYear,
// 		EndYear:               volunteerExperience.EndYear,
// 		Role:                  volunteerExperience.Role,
// 		Organization:          volunteerExperience.Organization,
// 		Cause:                 volunteerExperience.Cause,
// 		Description:           volunteerExperience.Description,
// 		CompanyLogo:           volunteerExperience.CompanyLogo,
// 		Url:                   volunteerExperience.Url,
// 	}

// 	// Save the volunteer experience entry to the database.
// 	if err := db.DB.Create(volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(volunteerExperience)
// }

// func GetVolunteerExperienceByUserID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Query the database for the user's volunteer experiences
// 	volunteerExperiences := []models.VolunteerExperience{}
// 	if err := db.DB.Where("volunteer_user_id = ?", userID).Find(&volunteerExperiences).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Volunteer experiences not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(volunteerExperiences)
// }

// func GetVolunteerExperienceByVolExpId(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Params("id")

// 	// Query the database for the user's volunteer experiences
// 	volunteerExperiences := []models.VolunteerExperience{}
// 	if err := db.DB.Where("volunteer_experience_id = ?", userID).Find(&volunteerExperiences).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Volunteer experiences not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(volunteerExperiences)
// }

// func UpdateVolunteerExperience(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var volunteerExperience models.VolunteerExperience
// 	if err := db.DB.Where("volunteer_user_id = ?", userID).First(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch volunteer experience details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userVolunteerExperience struct {
// 		StartMonth   *string `json:"start_month"`
// 		EndMonth     *string `json:"end_month"`
// 		StartYear    *string `json:"start_year"`
// 		EndYear      *string `json:"end_year"`
// 		Role         *string `json:"role"`
// 		Organization *string `json:"organization"`
// 		Cause        *string `json:"cause"`
// 		Description  *string `json:"description"`
// 		Location     *string `json:"location"`
// 		CompanyLogo  *string `json:"comapny_logo"`
// 		Url          *string `json:"url"`
// 	}

// 	if err := c.BodyParser(&userVolunteerExperience); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing volunteer experience
// 	if userVolunteerExperience.StartMonth != nil {
// 		volunteerExperience.StartMonth = *userVolunteerExperience.StartMonth
// 	}
// 	if userVolunteerExperience.EndMonth != nil {
// 		volunteerExperience.EndMonth = *userVolunteerExperience.EndMonth
// 	}
// 	if userVolunteerExperience.StartYear != nil {
// 		volunteerExperience.StartYear = *userVolunteerExperience.StartYear
// 	}
// 	if userVolunteerExperience.EndYear != nil {
// 		volunteerExperience.EndYear = *userVolunteerExperience.EndYear
// 	}
// 	if userVolunteerExperience.Role != nil {
// 		volunteerExperience.Role = *userVolunteerExperience.Role
// 	}
// 	if userVolunteerExperience.Organization != nil {
// 		volunteerExperience.Organization = *userVolunteerExperience.Organization
// 	}
// 	if userVolunteerExperience.Cause != nil {
// 		volunteerExperience.Cause = *userVolunteerExperience.Cause
// 	}
// 	if userVolunteerExperience.Description != nil {
// 		volunteerExperience.Description = *userVolunteerExperience.Description
// 	}
// 	if userVolunteerExperience.Location != nil {
// 		volunteerExperience.Location = *userVolunteerExperience.Location
// 	}
// 	if userVolunteerExperience.CompanyLogo != nil {
// 		volunteerExperience.CompanyLogo = *userVolunteerExperience.CompanyLogo
// 	}
// 	if userVolunteerExperience.Url != nil {
// 		volunteerExperience.Url = *userVolunteerExperience.Url
// 	}

// 	// Update the volunteer experience in the database
// 	if err := db.DB.Save(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update volunteer experience table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":              "Volunteer experience updated successfully",
// 		"volunteer_experience": volunteerExperience,
// 	})
// }

// func UpdateVolunteerExperienceByVoluntExpID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var volunteerExperience models.VolunteerExperience
// 	if err := db.DB.Where("volunteer_experience_id = ?", userID).First(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch volunteer experience details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userVolunteerExperience struct {
// 		StartMonth   *string `json:"start_month"`
// 		EndMonth     *string `json:"end_month"`
// 		StartYear    *string `json:"start_year"`
// 		EndYear      *string `json:"end_year"`
// 		Role         *string `json:"role"`
// 		Organization *string `json:"organization"`
// 		Cause        *string `json:"cause"`
// 		Description  *string `json:"description"`
// 		Location     *string `json:"location"`
// 		CompanyLogo  *string `json:"company_logo"`
// 		Url          *string `json:"url"`
// 	}

// 	if err := c.BodyParser(&userVolunteerExperience); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing volunteer experience
// 	if userVolunteerExperience.StartMonth != nil {
// 		volunteerExperience.StartMonth = *userVolunteerExperience.StartMonth
// 	}
// 	if userVolunteerExperience.EndMonth != nil {
// 		volunteerExperience.EndMonth = *userVolunteerExperience.EndMonth
// 	}
// 	if userVolunteerExperience.StartYear != nil {
// 		volunteerExperience.StartYear = *userVolunteerExperience.StartYear
// 	}
// 	if userVolunteerExperience.EndYear != nil {
// 		volunteerExperience.EndYear = *userVolunteerExperience.EndYear
// 	}
// 	if userVolunteerExperience.Role != nil {
// 		volunteerExperience.Role = *userVolunteerExperience.Role
// 	}
// 	if userVolunteerExperience.Organization != nil {
// 		volunteerExperience.Organization = *userVolunteerExperience.Organization
// 	}
// 	if userVolunteerExperience.Cause != nil {
// 		volunteerExperience.Cause = *userVolunteerExperience.Cause
// 	}
// 	if userVolunteerExperience.Description != nil {
// 		volunteerExperience.Description = *userVolunteerExperience.Description
// 	}
// 	if userVolunteerExperience.Location != nil {
// 		volunteerExperience.Location = *userVolunteerExperience.Location
// 	}
// 	if userVolunteerExperience.CompanyLogo != nil {
// 		volunteerExperience.CompanyLogo = *userVolunteerExperience.CompanyLogo
// 	}
// 	if userVolunteerExperience.Url != nil {
// 		volunteerExperience.Url = *userVolunteerExperience.Url
// 	}

// 	// Update the volunteer experience in the database
// 	if err := db.DB.Save(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update volunteer experience table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":              "Volunteer experience updated successfully",
// 		"volunteer_experience": volunteerExperience,
// 	})
// }

// func DeleteVolunteerExperienceByVolunteerExperienceID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	volunteerExperienceID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var volunteerExperience models.VolunteerExperience
// 	if err := db.DB.First(&volunteerExperience, volunteerExperienceID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Volunteer experience not found",
// 		})
// 	}

// 	// Delete the volunteer experience from the database
// 	if err := db.DB.Delete(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the volunteer experience",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Volunteer experience deleted successfully",
// 	})
// }

// func DeleteVolunteerExperienceByUserID(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var volunteerExperience models.VolunteerExperience
// 	if err := db.DB.Where("volunteer_user_id = ? ", userID).Find(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Volunteer experience not found",
// 		})
// 	}

// 	// Delete the volunteer experience from the database
// 	if err := db.DB.Delete(&volunteerExperience).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the volunteer experience",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Volunteer experience deleted successfully",
// 	})
// }

// func CreatePublication(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	publication := new(models.Publication)

// 	if err := c.BodyParser(publication); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	publication = &models.Publication{
// 		PublicationsID:    uuid.New(),
// 		PublicationUserID: userID,
// 		Title:             publication.Title,
// 		PublishedDate:     publication.PublishedDate,
// 		Publisher:         publication.Publisher,
// 		PublicationURL:    publication.PublicationURL,
// 		Description:       publication.Description,
// 	}

// 	// Save the publication entry to the database.
// 	if err := db.DB.Create(publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(publication)
// }

// func GetPublicationsByUserID(c *fiber.Ctx) error {
// 	// Get user ID from the token
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	// Query the database for the user's publications
// 	publications := []models.Publication{}
// 	if err := db.DB.Where("publication_user_id = ?", userID).Find(&publications).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Publications not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(publications)
// }

// func GetPublicationsByPubID(c *fiber.Ctx) error {
// 	// Get user ID from the token
// 	pubID := c.Params("id")

// 	// Query the database for the user's publications
// 	publications := models.Publication{}
// 	if err := db.DB.Where("publications_id = ?", pubID).Find(&publications).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Publications not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(publications)
// }
// func UpdatePublication(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var publication models.Publication
// 	if err := db.DB.Where("publication_user_id = ?", userID).First(&publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch publication details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userPublication struct {
// 		Title          *string `json:"title"`
// 		PublishedDate  *string `json:"published_date"`
// 		Publisher      *string `json:"publisher"`
// 		PublicationURL *string `json:"publication_url"`
// 		Description    *string `json:"description"`
// 	}

// 	if err := c.BodyParser(&userPublication); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing publication
// 	if userPublication.Title != nil {
// 		publication.Title = *userPublication.Title
// 	}
// 	if userPublication.PublishedDate != nil {
// 		publication.PublishedDate = *userPublication.PublishedDate
// 	}
// 	if userPublication.Publisher != nil {
// 		publication.Publisher = *userPublication.Publisher
// 	}
// 	if userPublication.PublicationURL != nil {
// 		publication.PublicationURL = *userPublication.PublicationURL
// 	}
// 	if userPublication.Description != nil {
// 		publication.Description = *userPublication.Description
// 	}

// 	// Update the publication in the database
// 	if err := db.DB.Save(&publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update publication table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":     "Publication updated successfully",
// 		"publication": publication,
// 	})
// }

// func UpdatePublicationByPubID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	pubID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var publication models.Publication
// 	if err := db.DB.Where("publications_id = ?", pubID).First(&publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch publication details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userPublication struct {
// 		Title          *string `json:"title"`
// 		PublishedDate  *string `json:"published_date"`
// 		Publisher      *string `json:"publisher"`
// 		PublicationURL *string `json:"publication_url"`
// 		Description    *string `json:"description"`
// 	}

// 	if err := c.BodyParser(&userPublication); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing publication
// 	if userPublication.Title != nil {
// 		publication.Title = *userPublication.Title
// 	}
// 	if userPublication.PublishedDate != nil {
// 		publication.PublishedDate = *userPublication.PublishedDate
// 	}
// 	if userPublication.Publisher != nil {
// 		publication.Publisher = *userPublication.Publisher
// 	}
// 	if userPublication.PublicationURL != nil {
// 		publication.PublicationURL = *userPublication.PublicationURL
// 	}
// 	if userPublication.Description != nil {
// 		publication.Description = *userPublication.Description
// 	}

// 	// Update the publication in the database
// 	if err := db.DB.Save(&publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update publication table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":     "Publication updated successfully",
// 		"publication": publication,
// 	})
// }

// func DeletePublication(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	publicationID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	fmt.Println("Publications delete")
// 	var publication models.Publication
// 	if err := db.DB.First(&publication, publicationID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Publication not found",
// 		})
// 	}

// 	// Delete the publication from the database
// 	if err := db.DB.Delete(&publication).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the publication",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Publication deleted successfully",
// 	})
// }

// func CreatePatent(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	patent := new(models.Patent)
// 	if err := c.BodyParser(patent); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	patent = &models.Patent{
// 		PatentID:     uuid.New(),
// 		PatentUserID: userID,
// 		Title:        patent.Title,
// 		PatentOffice: patent.PatentOffice,
// 		PatentNumber: patent.PatentNumber,
// 		IssueDate:    patent.IssueDate,
// 		Description:  patent.Description,
// 		Status:       patent.Status,
// 		Url:          patent.Url,
// 	}

// 	if err := db.DB.Create(patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(patent)
// }

// func GetPatents(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	patents := []models.Patent{}
// 	if err := db.DB.Where("patent_user_id = ?", userID).Find(&patents).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Patents not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(patents)
// }

// func GetPatentByPatentID(c *fiber.Ctx) error {
// 	userID := c.Params("id")

// 	patents := models.Patent{}
// 	if err := db.DB.Where("patent_id = ?", userID).Find(&patents).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Patents not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(patents)
// }

// func UpdatePatent(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var patent models.Patent
// 	if err := db.DB.Where("patent_user_id = ?", userID).First(&patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch patent details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userPatent struct {
// 		Title        *string `json:"title"`
// 		PatentOffice *string `json:"patent_office"`
// 		PatentNumber *string `json:"patent_number"`
// 		IssueDate    *string `json:"issue_date"`
// 		Description  *string `json:"description"`
// 		Status       *string `json:"status"`
// 		Url          *string `json:"url"`
// 	}

// 	if err := c.BodyParser(&userPatent); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if userPatent.Title != nil {
// 		patent.Title = *userPatent.Title
// 	}
// 	if userPatent.PatentOffice != nil {
// 		patent.PatentOffice = *userPatent.PatentOffice
// 	}
// 	if userPatent.PatentNumber != nil {
// 		patent.PatentNumber = *userPatent.PatentNumber
// 	}
// 	if userPatent.IssueDate != nil {
// 		patent.IssueDate = *userPatent.IssueDate
// 	}
// 	if userPatent.Description != nil {
// 		patent.Description = *userPatent.Description
// 	}
// 	if userPatent.Status != nil {
// 		patent.Status = *userPatent.Status
// 	}
// 	if userPatent.Url != nil {
// 		patent.Url = *userPatent.Url
// 	}

// 	if err := db.DB.Save(&patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update patent table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Patent updated successfully",
// 		"patent":  patent,
// 	})
// }

// func UpdatePatentByPatentID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	patID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var patent models.Patent
// 	if err := db.DB.Where("patent_id = ?", patID).First(&patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch patent details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userPatent struct {
// 		Title        *string `json:"title"`
// 		PatentOffice *string `json:"patent_office"`
// 		PatentNumber *string `json:"patent_number"`
// 		IssueDate    *string `json:"issue_date"`
// 		Description  *string `json:"description"`
// 		Status       *string `json:"status"`
// 		Url          *string `json:"url"`
// 	}

// 	if err := c.BodyParser(&userPatent); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	if userPatent.Title != nil {
// 		patent.Title = *userPatent.Title
// 	}
// 	if userPatent.PatentOffice != nil {
// 		patent.PatentOffice = *userPatent.PatentOffice
// 	}
// 	if userPatent.PatentNumber != nil {
// 		patent.PatentNumber = *userPatent.PatentNumber
// 	}
// 	if userPatent.IssueDate != nil {
// 		patent.IssueDate = *userPatent.IssueDate
// 	}
// 	if userPatent.Description != nil {
// 		patent.Description = *userPatent.Description
// 	}
// 	if userPatent.Status != nil {
// 		patent.Status = *userPatent.Status
// 	}
// 	if userPatent.Url != nil {
// 		patent.Url = *userPatent.Url
// 	}

// 	if err := db.DB.Save(&patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update patent table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Patent updated successfully",
// 		"patent":  patent,
// 	})
// }
// func DeletePatentByPatentID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	patentID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var patent models.Patent
// 	if err := db.DB.First(&patent, patentID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Patent not found",
// 		})
// 	}

// 	if err := db.DB.Delete(&patent).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the patent",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Patent deleted successfully",
// 	})
// }

// func CreateTestScore(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the request body into a TestScore struct
// 	var testScore models.TestScore
// 	if err := c.BodyParser(&testScore); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	testScore = models.TestScore{
// 		TestScoreID:     uuid.New(),
// 		TestScoreUserID: uuid.MustParse(userID),
// 		TestName:        testScore.TestName,
// 		Score:           testScore.Score,
// 		Date:            testScore.Date,
// 		Description:     testScore.Description,
// 		Associated:      testScore.Associated,
// 	}

// 	// Save the test score entry to the database
// 	if err := db.DB.Create(&testScore).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(testScore)
// }

// func GetTestScores(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Params("id")

// 	// Query the database for the user's test scores
// 	testScores := []models.TestScore{}
// 	if err := db.DB.Where("test_score_user_id = ?", userID).Find(&testScores).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Test scores not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(testScores)
// }

// func GetTestScoreByID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Params("id")

// 	// Query the database for the user's test scores
// 	testScores := models.TestScore{}
// 	if err := db.DB.Where("test_score_id = ?", userID).Find(&testScores).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Test scores not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(testScores)
// }

// func UpdateTestScoreByTSID(c *fiber.Ctx) error {
// 	// Parse test score ID from the request
// 	testScoreID := c.Params("id")

// 	var testScore models.TestScore
// 	if err := db.DB.Where("test_score_id = ?", testScoreID).First(&testScore).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch test score details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var updatedTestScore struct {
// 		TestName    *string  `json:"test_name"`
// 		Score       *float64 `json:"score"`
// 		Date        *string  `json:"date"`
// 		Description *string  `json:"description"`
// 		Associated  *string  `json:"associated"`
// 	}
// 	// Parse the request body into a TestScore struct
// 	if err := c.BodyParser(&updatedTestScore); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Update the test score fields
// 	if updatedTestScore.TestName != nil {
// 		testScore.TestName = *updatedTestScore.TestName
// 	}
// 	if updatedTestScore.Score != nil {
// 		testScore.Score = *updatedTestScore.Score

// 	}
// 	if updatedTestScore.Date != nil {
// 		testScore.Date = *updatedTestScore.Date
// 	}
// 	if updatedTestScore.Description != nil {
// 		testScore.Description = *updatedTestScore.Description
// 	}
// 	if updatedTestScore.Associated != nil {
// 		testScore.Associated = *updatedTestScore.Associated
// 	}

// 	if err := db.DB.Save(&testScore).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update test score table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":    "Test score updated successfully",
// 		"test_score": testScore,
// 	})
// }

// func DeleteTestScore(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse test score ID from the request
// 	testScoreID := c.Params("id")

// 	var testScore models.TestScore
// 	if err := db.DB.Where("test_score_user_id = ? AND test_score_id = ?", userID, testScoreID).First(&testScore).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Test score not found",
// 		})
// 	}

// 	// Delete the test score from the database
// 	if err := db.DB.Delete(&testScore).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the test score",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Test score deleted successfully",
// 	})
// }

// func CreateOrganization(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Parse the request body into an Organization struct
// 	org := new(models.Organization)
// 	if err := c.BodyParser(&org); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	// Set the user ID and create a new organization entry
// 	org = &models.Organization{
// 		OrganizationID:     uuid.New(),
// 		OrganizationUserID: userID,
// 		Name:               org.Name,
// 		Position:           org.Position,
// 		StartMonth:         org.StartMonth,
// 		EndMonth:           org.EndMonth,
// 		StartYear:          org.StartYear,
// 		EndYear:            org.EndYear,
// 		Description:        org.Description,
// 	}

// 	// Save the organization entry to the database
// 	if err := db.DB.Create(&org).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(org)
// }

// func GetOrganizations(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Query the database for the user's organizations
// 	organizations := []models.Organization{}
// 	if err := db.DB.Where("organization_user_id = ?", userID).Find(&organizations).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(organizations)
// }

// func GetOrganizationByOrgID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	orgID := c.Params("id")

// 	// Query the database for the user's organizations
// 	organizations := models.Organization{}
// 	if err := db.DB.Where("organization_id = ?", orgID).Find(&organizations).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(organizations)
// }

// func UpdateOrganizationByOrgID(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var org models.Organization
// 	if err := db.DB.Where("organization_user_id = ?", userID).First(&org).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "Failed to fetch organization details",
// 			"error": err.Error(),
// 		})
// 	}

// 	var userOrg struct {
// 		Name        *string `json:"name"`
// 		Position    *string `json:"position"`
// 		StartMonth  *string `json:"start_month"`
// 		EndMonth    *string `json:"end_month"`
// 		StartYear   *string `json:"start_year"`
// 		EndYear     *string `json:"end_year"`
// 		Description *string `json:"description"`
// 	}

// 	if err := c.BodyParser(&userOrg); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Merge the changes into the existing organization
// 	if userOrg.Name != nil {
// 		org.Name = *userOrg.Name
// 	}
// 	if userOrg.Position != nil {
// 		org.Position = *userOrg.Position
// 	}
// 	if userOrg.StartMonth != nil {
// 		org.StartMonth = *userOrg.StartMonth
// 	}
// 	if userOrg.EndMonth != nil {
// 		org.EndMonth = *userOrg.EndMonth
// 	}
// 	if userOrg.StartYear != nil {
// 		org.StartYear = *userOrg.StartYear
// 	}
// 	if userOrg.EndYear != nil {
// 		org.EndYear = *userOrg.EndYear
// 	}
// 	if userOrg.Description != nil {
// 		org.Description = *userOrg.Description
// 	}

// 	// Update the organization in the database
// 	if err := db.DB.Save(&org).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update organization table",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":      "Organization updated successfully",
// 		"organization": org,
// 	})
// }

// func DeleteOrganizationByOrgID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	orgID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	var org models.Organization
// 	if err := db.DB.First(&org, orgID).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Organization not found",
// 		})
// 	}

// 	// Delete the organization from the database
// 	if err := db.DB.Delete(&org).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to delete the organization",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Organization deleted successfully",
// 	})
// }

// func CreateCause(c *fiber.Ctx) error {

// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Parse the request body into a Cause struct
// 	var cause models.Cause
// 	if err := c.BodyParser(&cause); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	cause = models.Cause{
// 		CauseID:     uuid.New(),
// 		CauseUserID: userID,
// 		Name:        cause.Name,
// 	}

// 	causeResponse := models.CauseResponse{
// 		CauseID:     cause.CauseID,
// 		CauseUserID: userID,
// 		Name:        cause.Name,
// 	}

// 	if err := db.DB.Create(&causeResponse).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	fmt.Println("cause ", cause)
// 	fmt.Printf("Cause response %T\n", causeResponse.Name)
// 	return c.Status(fiber.StatusCreated).JSON(causeResponse)
// }

// func getStringArray(names pq.StringArray) []string {
// 	return []string(names)
// }

// func GetAllCauseByUserID(c *fiber.Ctx) error {
// 	// Parse cause ID from the request
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	// Query the database for the cause
// 	causes := []models.CauseResponse{}
// 	if err := db.DB.Where("cause_user_id = ?", userID).Find(&causes).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Cause not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	// Create a slice to hold the response data
// 	var response []map[string]interface{}

// 	// Iterate through causes and create response data
// 	for _, cause := range causes {
// 		response = append(response, map[string]interface{}{
// 			"cause_id":      cause.CauseID,
// 			"cause_user_id": cause.CauseUserID,
// 			"name":          getStringArray(cause.Name),
// 		})
// 	}

// 	// Send the JSON response
// 	return c.Status(fiber.StatusOK).JSON(response)
// }

// func UpdateCause(c *fiber.Ctx) error {
// 	// Parse the request body into a Cause struct
// 	var updateCauseRes models.CauseResponse
// 	if err := c.BodyParser(&updateCauseRes); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	// Update the cause response in the database based on CauseID and CauseUserID
// 	if err := db.DB.Model(&models.CauseResponse{}).Where("cause_id = ? AND cause_user_id = ?", updateCauseRes.CauseID, updateCauseRes.CauseUserID).Updates(map[string]interface{}{
// 		"name": updateCauseRes.Name,
// 	}).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to update cause response in the database",
// 		})
// 	}

// 	// Return a success response
// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Cause and cause response updated successfully",
// 		"cause":   updateCauseRes,
// 	})
// }

// func DeleteCauseByCauseID(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	causeID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	// Delete cause responses
// 	if err := db.DB.Where("cause_id = ?", causeID).Delete(&models.CauseResponse{}).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete cause responses",
// 		})
// 	}

// 	// Delete the cause
// 	if err := db.DB.Where("cause_id = ?", causeID).Delete(&models.Cause{}).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete cause",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Cause and associated responses deleted successfully",
// 	})
// }

// func CreateRecommendation(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the request body into a Recommendation struct
// 	var recommendation models.Recommendation
// 	if err := c.BodyParser(&recommendation); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	recommendation = models.Recommendation{
// 		RecommendationID:    uuid.New(),
// 		UserID:              uuid.MustParse(userID),
// 		RecommenderName:     recommendation.RecommenderName,
// 		RecommenderPosition: recommendation.RecommenderPosition,
// 		Relationship:        recommendation.Relationship,
// 		RecommendationText:  recommendation.RecommendationText,
// 		CreatedAt:           time.Now(),
// 	}

// 	// Save the recommendation to the database
// 	if err := db.DB.Create(&recommendation).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(recommendation)
// }

// func GetRecommendations(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Query the database for the user's recommendations
// 	recommendations := []models.Recommendation{}
// 	if err := db.DB.Where("user_id = ?", userID).Find(&recommendations).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Recommendations not found for this user",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(recommendations)
// }

// func UpdateRecommendationByRecID(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the recommendation ID from the request
// 	recommendationID := c.Params("id")

// 	var recommendation models.Recommendation
// 	if err := db.DB.Where("recommendation_id = ? AND user_id = ?", recommendationID, userID).First(&recommendation).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error": "Recommendation not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to fetch recommendation details",
// 		})
// 	}

// 	var updatedRecommendation struct {
// 		RecommenderName     *string `json:"recommender_name"`
// 		RecommenderPosition *string `json:"recommender_position"`
// 		Relationship        *string `json:"relationship"`
// 		RecommendationText  *string `json:"recommendation_text"`
// 	}

// 	// Parse the request body into an updatedRecommendation struct
// 	if err := c.BodyParser(&updatedRecommendation); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Update the recommendation fields
// 	if updatedRecommendation.RecommenderName != nil {
// 		recommendation.RecommenderName = *updatedRecommendation.RecommenderName
// 	}
// 	if updatedRecommendation.RecommenderPosition != nil {
// 		recommendation.RecommenderPosition = *updatedRecommendation.RecommenderPosition
// 	}
// 	if updatedRecommendation.Relationship != nil {
// 		recommendation.Relationship = *updatedRecommendation.Relationship
// 	}
// 	if updatedRecommendation.RecommendationText != nil {
// 		recommendation.RecommendationText = *updatedRecommendation.RecommendationText
// 	}

// 	// Update the recommendation in the database
// 	if err := db.DB.Save(&recommendation).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": "Failed to update recommendation",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":        "Recommendation updated successfully",
// 		"recommendation": recommendation,
// 	})
// }
// func DeleteRecommendationByID(c *fiber.Ctx) error {
// 	// Parse the RecommendationID from the request parameters
// 	recommendationID := c.Params("id")

// 	// Convert the RecommendationID string to a UUID
// 	recommendationUUID, err := uuid.Parse(recommendationID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid RecommendationID",
// 		})
// 	}

// 	// Check if the recommendation exists in the database
// 	var recommendation models.Recommendation
// 	if err := db.DB.Where("recommendation_id = ?", recommendationUUID).First(&recommendation).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Recommendation not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete recommendation",
// 		})
// 	}

// 	// Delete the recommendation
// 	if err := db.DB.Delete(&recommendation).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete recommendation",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Recommendation deleted successfully",
// 	})
// }

// func CreateGroup(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	userID := c.Locals("id").(string)

// 	// Parse the request body into a Group struct
// 	var group *models.Group
// 	if err := c.BodyParser(&group); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	group = &models.Group{
// 		GroupID:     uuid.New(),
// 		Name:        group.Name,
// 		Description: group.Description,
// 	}

// 	// Save the group to the database
// 	if err := db.DB.Create(&group).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	// Create a GroupMember entry for the creator
// 	groupMember := &models.GroupMember{
// 		GroupMemberID: uuid.New(),
// 		GroupID:       group.GroupID,
// 		UserID:        uuid.MustParse(userID),
// 	}

// 	// Save the group member to the database
// 	if err := db.DB.Create(&groupMember).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(group)
// }

// func JoinGroup(c *fiber.Ctx) error {
// 	// Parse user ID from the request
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Parse the group ID from the request parameters
// 	groupID := c.Params("groupID")
// 	groupUUID, err := StringToUUID(groupID)
// 	if err != nil {
// 		return err
// 	}

// 	// Check if the user is already a member of the group
// 	var existingMember models.GroupMember
// 	if err := db.DB.Where("user_id = ? AND group_id = ?", userID, groupUUID).First(&existingMember).Error; err == nil {
// 		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "User is already a member of the group",
// 		})
// 	}

// 	// Create a new GroupMember entry to represent the user's membership
// 	newMember := models.GroupMember{
// 		GroupMemberID: uuid.New(),
// 		GroupID:       groupUUID,
// 		UserID:        userID,
// 	}

// 	if err := db.DB.Create(&newMember).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to join the group",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Joined the group successfully",
// 	})
// }

// func LeaveGroup(c *fiber.Ctx) error {
// 	// Parse group ID from the request parameters
// 	groupID := c.Params("groupID")
// 	groupIDUUID, err := StringToUUID(groupID)
// 	if err != nil {
// 		return err
// 	}
// 	// Parse user ID from the request (you can retrieve it from authentication)
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Check if the user is a member of the group
// 	var groupMember models.GroupMember
// 	if err := db.DB.
// 		Where("group_id = ? AND user_id = ?", groupIDUUID, userID).
// 		First(&groupMember).
// 		Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "User is not a member of the group",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch group membership",
// 		})
// 	}

// 	// Delete the group membership
// 	if err := db.DB.Delete(&groupMember).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to leave the group",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Left the group successfully",
// 	})
// }

// func GetUserGroups(c *fiber.Ctx) error {
// 	// Parse user ID from the request (you can retrieve it from authentication)
// 	id := c.Params("id")
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Query the database for the groups that the user belongs to
// 	var groups []models.Group

// 	if err := db.DB.Raw(`
//         SELECT g.*
//         FROM groups g
//         JOIN group_members gm ON g.group_id = gm.group_id
//         WHERE gm.user_id = ?`, userID).Scan(&groups).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch user's groups",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(groups)
// }

// type GroupPostJSON struct {
// 	PostUserID    uuid.UUID                 `json:"user_id"`
// 	GroupID       uuid.UUID                 `json:"group_id"`
// 	PostTitle     string                    `json:"title"`
// 	PostContent   string                    `json:"content"`
// 	PostImage     string                    `json:"image"`
// 	PostVideo     string                    `json:"video"`
// 	PostURL       string                    `json:"url"`
// 	Dislikes      int                       `json:"dislikes"`
// 	Likers        pq.StringArray            `gorm:"type:text[]" json:"likers"`
// 	Dislikers     pq.StringArray            `gorm:"type:uuid[]" json:"dislikers"`
// 	Comments      []models.GroupPostComment ` json:"comments"`
// 	Likes         []models.GroupPostLike    `json:"likes"`
// 	LikesCount    int                       `json:"likes_count"`
// 	CommentCount  int                       `json:"comment_count"`
// 	TaggedUserIDs pq.StringArray            `json:"tagged_user_ids"`
// 	// Add other fields from the Post struct as needed
// 	Hashtags  []string       `json:"hashtags"`
// 	Mentions  pq.StringArray `gorm:"type:text[]" json:"mentions"`
// 	CreatedAt time.Time      `json:"created_at"`
// 	UpdatedAt time.Time      `json:"updated_at"`
// }

// func ConvertToGroupPost(postJSON GroupPostJSON, postUserID uuid.UUID) models.GroupPost {
// 	hashtags := make([]models.Hashtag, len(postJSON.Hashtags))
// 	for i, hashtagName := range postJSON.Hashtags {
// 		// Check if the hashtag already exists
// 		var existingHashtag models.Hashtag
// 		if err := db.DB.Where("name = ?", hashtagName).First(&existingHashtag).Error; err != nil {
// 			// If the hashtag doesn't exist, create a new one with a new UUID
// 			if errors.Is(err, gorm.ErrRecordNotFound) {
// 				newHashtag := models.Hashtag{
// 					HashtagID: uuid.New(),
// 					Name:      hashtagName,
// 				}

// 				// Save the new hashtag to the database
// 				if err := db.DB.Create(&newHashtag).Error; err != nil {
// 					// Handle the error as needed
// 					fmt.Printf("Error creating new hashtag: %v\n", err)
// 					return models.GroupPost{}
// 				}

// 				hashtags[i] = newHashtag
// 			} else {
// 				// Handle other errors
// 				// You may want to log the error or handle it based on your requirements
// 				fmt.Printf("Error retrieving existing hashtag: %v\n", err)
// 				// You can choose to return an empty Post or handle the error in another way
// 				return models.GroupPost{}
// 			}
// 		} else {
// 			// If the hashtag exists, reuse its ID
// 			hashtags[i] = existingHashtag
// 		}
// 	}
// 	fmt.Println("In post json ", postJSON)
// 	return models.GroupPost{
// 		PostID:        uuid.New(),
// 		UserID:        postUserID,
// 		GroupID:       postJSON.GroupID,
// 		Title:         postJSON.PostTitle,
// 		Content:       postJSON.PostContent,
// 		Image:         postJSON.PostImage,
// 		Video:         postJSON.PostVideo,
// 		URL:           postJSON.PostURL,
// 		Likes:         postJSON.Likes,
// 		Comments:      postJSON.Comments,
// 		Likers:        postJSON.Likers,
// 		Dislikes:      postJSON.Dislikes,
// 		Dislikers:     postJSON.Dislikers,
// 		TaggedUserIDs: postJSON.TaggedUserIDs,
// 		Hashtags:      hashtags,
// 		Mentions:      postJSON.Mentions,
// 		LikesCount:    postJSON.LikesCount,
// 		CommentCount:  postJSON.CommentCount,
// 	}
// }

// // generateUniqueURL generates a unique URL based on the first three words of the input string
// func generateUnqURL(title string, currentPostID uuid.UUID) string {
// 	// Extract the first three words from the title
// 	words := strings.Fields(title)
// 	var truncatedWords []string
// 	if len(words) > 3 {
// 		truncatedWords = words[:3]
// 	} else {
// 		truncatedWords = words
// 	}

// 	// Combine the truncated words with hyphens
// 	url := strings.Join(truncatedWords, "-")
// 	url = strings.ToLower(url)
// 	// Check if the URL is already taken, and if so, append a random string
// 	uniqueURL := url
// 	for {
// 		if isURLTkn(uniqueURL, currentPostID) {
// 			uniqueURL = url + "-" + generateRandomString(4)
// 		} else {
// 			break
// 		}
// 	}
// 	return uniqueURL
// }

// // isURLTaken checks if the given URL is already taken, excluding the current post
// func isURLTkn(url string, currentPostID uuid.UUID) bool {
// 	var count int64
// 	db.DB.Model(&models.GroupPost{}).Where("url = ? AND post_id != ?", url, currentPostID).Count(&count)
// 	return count > 0
// }

// // Create a new group post
// func CreateGroupPost(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	groupPostUserID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	// Parse the user's input from the request and create a new GroupPost
// 	groupPostJSON := new(GroupPostJSON)
// 	if err := c.BodyParser(&groupPostJSON); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":     true,
// 			"message":   "Invalid request body",
// 			"error got": err.Error(),
// 		})
// 	}
// 	// Convert PostJSON to Post
// 	groupPost := ConvertToGroupPost(*groupPostJSON, groupPostUserID)
// 	groupPostID := uuid.New()
// 	// Generate a unique URL based on the first three words of the post title

// 	url := generateUnqURL(groupPost.Content, groupPostID)

// 	fmt.Println("group post from json", groupPost)
// 	// Regular expression to match mentions or tags in the updated post content
// 	mentionRegex := regexp.MustCompile(`@(\w+)`)

// 	// Find all matches in the updated post content
// 	matches := mentionRegex.FindAllStringSubmatch(groupPost.Content, -1)

// 	taggedUserIDs := make(pq.StringArray, len(matches))
// 	for i, match := range matches {
// 		if len(match) == 2 {
// 			parsedUserID, err := uuid.Parse(match[1])
// 			if err == nil {
// 				taggedUserIDs[i] = parsedUserID.String()
// 			}
// 		}
// 	}

// 	// Handle existence of tagged users
// 	if groupPost.TaggedUserIDs != nil {
// 		existingUsers := make([]models.User, 0)
// 		// COnverting taggedUserIDs to uuid.UUID[]
// 		var taggedUserIDsExUser []uuid.UUID

// 		for _, idStr := range groupPost.TaggedUserIDs {
// 			parsedID, err := uuid.Parse(idStr)
// 			if err != nil {
// 				// Handle the error if the parsing fails
// 				return err
// 			}

// 			taggedUserIDsExUser = append(taggedUserIDsExUser, parsedID)
// 		}

// 		if err := db.DB.Where("uuid IN ?", taggedUserIDsExUser).Find(&existingUsers).Error; err != nil {
// 			return c.Status(500).JSON(fiber.Map{
// 				"error":     "Database error",
// 				"error_msg": err.Error(),
// 			})
// 		}

// 		// Check if all tagged users exist
// 		for _, userID := range groupPost.TaggedUserIDs {
// 			userExists := false
// 			// Manual check by iterating over existing users
// 			for _, existingUser := range existingUsers {
// 				if existingUser.UUID.String() == userID {
// 					taggedUserIDs = append(taggedUserIDs, userID)
// 					userExists = true
// 					break
// 				}
// 			}
// 			if !userExists {
// 				fmt.Println("User does not exist with ID:", userID)

// 				return c.Status(400).JSON(fiber.Map{
// 					"error":   true,
// 					"message": "One or more tagged users do not exist",
// 				})
// 			}

// 			// Send notification to each tagged user
// 			dbHandler := &db.DBHandlerImpl{
// 				DB: db.DB}

// 			notificationService := services.NewNotificationService(dbHandler)
// 			notificationMessage := fmt.Sprintf("You have been tagged in a post: %s", groupPost.Title)
// 			notificationService.SendNotification(uuid.MustParse(userID), notificationMessage, "tagged_in_post", url)
// 		}

// 	}

// 	tx := db.DB.Begin()

// 	hashtags := extractHashtags(groupPost.Content)
// 	fmt.Println("Hashtags ", hashtags)
// 	// Ensure unique hashtags before association
// 	uniqueHashtags := make(map[string]bool)
// 	for _, hashtagName := range hashtags {
// 		uniqueHashtags[hashtagName] = true
// 	}

// 	// Create or update associated hashtags
// 	for hashtagName := range uniqueHashtags {
// 		var hashtag models.Hashtag

// 		// Check if the hashtag already exists
// 		if err := db.DB.Where("name = ?", hashtagName).First(&hashtag).Error; err != nil {
// 			// If the hashtag doesn't exist, create a new one with a new UUID
// 			if errors.Is(err, gorm.ErrRecordNotFound) {
// 				newHashtag := models.Hashtag{
// 					HashtagID: uuid.New(),
// 					Name:      hashtagName,
// 				}

// 				// Create the new hashtag
// 				if err := db.DB.Create(&newHashtag).Error; err != nil {
// 					return err
// 				}

// 				// Associate the new hashtag with the post
// 				groupPost.Hashtags = append(groupPost.Hashtags, newHashtag)
// 				fmt.Println("post hashtag ,", groupPost.Hashtags)
// 			} else {
// 				// Handle other errors
// 				return err
// 			}
// 		} else {
// 			// If the hashtag exists, just append it to the post's hashtags
// 			groupPost.Hashtags = append(groupPost.Hashtags, hashtag)
// 			fmt.Println("post hashtag ", groupPost.Hashtags)

// 		}
// 	}

// 	groupPost = models.GroupPost{
// 		PostID:        groupPostID,
// 		UserID:        groupPostUserID,
// 		GroupID:       groupPost.GroupID,
// 		Title:         groupPost.Title,
// 		Content:       groupPost.Content,
// 		Image:         groupPost.Image,
// 		Video:         groupPost.Video,
// 		URL:           url,
// 		Likes:         groupPost.Likes,
// 		Likers:        groupPost.Likers,
// 		LikesCount:    groupPost.LikesCount,
// 		Dislikes:      groupPost.Dislikes,
// 		Dislikers:     groupPost.Dislikers,
// 		Comments:      groupPost.Comments,
// 		CommentCount:  groupPost.CommentCount,
// 		Hashtags:      groupPost.Hashtags,
// 		Mentions:      groupPost.Mentions,
// 		TaggedUserIDs: taggedUserIDs,
// 		CreatedAt:     time.Now(),
// 		UpdatedAt:     time.Now(),
// 	}

// 	result := tx.Create(&groupPost)
// 	if result.Error != nil {
// 		// Rollback the transaction in case of an error
// 		tx.Rollback()
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to create post table",
// 		})
// 	}
// 	// Commit the transaction if everything is successful
// 	tx.Commit()

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Post created successfully",
// 		"post":    groupPost,
// 	})
// }

// func GetGroupPosts(c *fiber.Ctx) error {
// 	groupID := c.Params("groupID")

// 	// Query the database for group posts by group ID
// 	groupPosts := []models.GroupPost{}
// 	if err := db.DB.Where("group_id = ?", groupID).Find(&groupPosts).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "No group posts found for this group",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(groupPosts)
// }

// func GetGroupPostByPostID(c *fiber.Ctx) error {
// 	groupID := c.Params("groupID")
// 	postID := c.Params("postID")
// 	// Query the database for group posts by group ID
// 	groupPosts := models.GroupPost{}
// 	if err := db.DB.Where("group_id = ? AND post_id = ?", groupID, postID).Find(&groupPosts).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "No group posts found for this group",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(groupPosts)
// }

// func UpdateGroupPost(c *fiber.Ctx) error {
// 	// Parse the GroupPostID from the request parameters
// 	groupPostID := c.Params("groupPostID")

// 	// Convert the GroupPostID string to a UUID
// 	groupPostUUID, err := uuid.Parse(groupPostID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid GroupPostID",
// 		})
// 	}

// 	// Check if the group post exists in the database
// 	var groupPost models.GroupPost
// 	if err := db.DB.Where("post_id = ?", groupPostUUID).First(&groupPost).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Group post not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch group post details",
// 		})
// 	}

// 	var updatedGroupPost struct {
// 		Content string `json:"content"`
// 		// Add other fields you want to update here
// 	}

// 	// Parse the request body into an updatedGroupPost struct
// 	if err := c.BodyParser(&updatedGroupPost); err != nil {
// 		return c.JSON(fiber.Map{
// 			"error": err.Error(),
// 			"input": "Please review your input",
// 		})
// 	}

// 	// Update the group post fields
// 	if updatedGroupPost.Content != "" {
// 		groupPost.Content = updatedGroupPost.Content
// 	}
// 	// Update other fields as needed

// 	// Update the group post in the database
// 	if err := db.DB.Save(&groupPost).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to update group post",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":   "Group post updated successfully",
// 		"groupPost": groupPost,
// 	})
// }

// func DeleteGroupPost(c *fiber.Ctx) error {
// 	// Parse the GroupPostID from the request parameters
// 	groupPostID := c.Params("groupPostID")

// 	// Convert the GroupPostID string to a UUID
// 	groupPostUUID, err := uuid.Parse(groupPostID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid GroupPostID",
// 		})
// 	}

// 	// Check if the group post exists in the database
// 	var groupPost models.GroupPost
// 	if err := db.DB.Where("post_id = ?", groupPostUUID).First(&groupPost).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Group post not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete group post",
// 		})
// 	}

// 	// Delete the group post
// 	if err := db.DB.Delete(&groupPost).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete group post",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Group post deleted successfully",
// 	})
// }

// // CreateGroupPostComment creates a new comment for a group post.
// func CreateGroupPostComment(c *fiber.Ctx) error {
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}
// 	id1 := c.Params("groupPostID")
// 	groupPostID, err := StringToUUID(id1)
// 	if err != nil {
// 		return err
// 	}

// 	// Parse the request body into a Comment struct
// 	comment := new(models.GroupPostComment)
// 	if err := c.BodyParser(comment); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	comment = &models.GroupPostComment{
// 		GroupPostCommentID: uuid.New(),
// 		UserID:             userID,
// 		Content:            comment.Content,
// 		PostID:             groupPostID,
// 		CreatedAt:          time.Now(),
// 	}
// 	// Save the comment to the database
// 	result := db.DB.Create(&comment)

// 	if result.Error != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}
// 	// Fetch the user ID of the post creator (replace with your actual logic)
// 	groupPost := models.GroupPost{}
// 	if err := db.DB.Where("post_id = ? ", comment.PostID).Find(&groupPost).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Failed to fetch post details",
// 		})
// 	}
// 	groupPostCreatorID := groupPost.UserID
// 	fmt.Println("group post creator ID", groupPostCreatorID)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to get post creator",
// 		})
// 	}

// 	// Update GroupPost fields

// 	groupPost.CommentCount++
// 	groupPost.Comments = append(groupPost.Comments, *comment)

// 	// Save the updated GroupPost to the database
// 	result = db.DB.Save(&groupPost)
// 	if result.Error != nil {
// 		// Handle the error
// 		fmt.Printf("Failed to update GroupPost: %v\n", result.Error)
// 		return result.Error
// 	}
// 	// Create a notification
// 	notification := &notifications.Notification{
// 		NotificationID: uuid.New(),
// 		RecipientID:    groupPostCreatorID, // The user who created the post
// 		Message:        "You have a new comment on your post.",
// 		IsRead:         false,
// 		CreatedAt:      time.Now(),
// 		URL:            groupPost.URL,
// 	}

// 	// Save the notification in the database
// 	result = db.DB.Create(&notification)
// 	if result.Error != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to create notification",
// 		})
// 	}

// 	dbHandler := &db.DBHandlerImpl{
// 		DB: db.DB,
// 	}

// 	// Send a notification to the post creator
// 	notificationService := services.NewNotificationService(dbHandler)
// 	notificationService.SendNotification(groupPostCreatorID, notification.Message, "comment", groupPost.URL)

// 	return c.Status(fiber.StatusCreated).JSON(comment)
// }

// // UpdateGroupPostComment updates an existing group post comment.
// func UpdateGroupPostComment(c *fiber.Ctx) error {
// 	groupPostID := c.Params("groupPostID")
// 	commentID := c.Params("commentID")

// 	// Check if the comment exists
// 	var comment models.GroupPostComment
// 	if err := db.DB.Where("group_post_comment_id = ? AND post_id = ?", commentID, groupPostID).First(&comment).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Comment not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch comment details",
// 		})
// 	}

// 	// Parse the request body into an updated Comment struct
// 	var updatedComment models.Comment
// 	if err := c.BodyParser(&updatedComment); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	// Update the comment fields
// 	comment.Content = updatedComment.Content
// 	comment.UpdatedAt = time.Now()

// 	// Update the comment in the database
// 	if err := db.DB.Save(&comment).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to update comment",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(comment)
// }

// // GetGroupPostComments gets comments for a specific group post.
// func GetGroupPostComments(c *fiber.Ctx) error {
// 	groupPostID := c.Params("groupPostID")

// 	var comments []models.Comment
// 	if err := db.DB.Where("post_id = ?", groupPostID).Find(&comments).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Comments not found for this group post",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(comments)
// }

// // DeleteGroupPostComment deletes a group post comment.
// func DeleteGroupPostComment(c *fiber.Ctx) error {
// 	groupPostID := c.Params("groupPostID")
// 	commentID := c.Params("commentID")

// 	// Check if the comment exists
// 	var comment models.Comment
// 	if err := db.DB.Where("group_post_comment_id = ? AND post_id = ?", commentID, groupPostID).First(&comment).Error; err != nil {
// 		if err.Error() == "record not found" {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Comment not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch comment details",
// 		})
// 	}

// 	// Delete the comment
// 	if err := db.DB.Delete(&comment).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to delete comment",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Comment deleted successfully",
// 	})
// }

// func GetAllNotifications(c *fiber.Ctx) error {

// 	var notifications []notifications.Notification
// 	if err := db.DB.Find(&notifications).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to retrieve notifications",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(notifications)
// }

// func CreateGroupPostLike(c *fiber.Ctx) error {
// 	// Parse user ID from the request or any authentication method.
// 	id := c.Locals("id").(string)
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	fmt.Println("User ID ", userID)
// 	// Parse the group post ID from the request.
// 	id1 := c.Params("groupPostID")
// 	groupPostID, err := StringToUUID(id1)
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch the group post
// 	groupPost := models.GroupPost{}
// 	if err := db.DB.Where("post_id = ?", groupPostID).First(&groupPost).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Failed to fetch group post details",
// 		})
// 	}

// 	// Check if the user has already liked the post.
// 	// Query the database to see if a like entry exists for this user and post.

// 	existingLike := models.GroupPostLike{}
// 	if err := db.DB.Where("group_post_id = ? AND user_id = ?", groupPostID, userID).First(&existingLike).Error; err == nil {
// 		// If a like entry already exists, the user has already liked the post.

// 		groupPost.LikesCount--
// 		groupPost.Likers = removeFromArray(groupPost.Likers, userID)
// 		if err := db.DB.Save(&groupPost).Error; err != nil {
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 				"error": true,
// 				"input": "Failed to update like status",
// 			})
// 		}

// 		if err := db.DB.Where("group_post_id = ? AND user_id = ?", groupPostID, userID).Delete(&models.GroupPostLike{}).Error; err != nil {
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Failed to delete group post like",
// 			})
// 		}
// 		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Your like has been removed",
// 		})
// 	}

// 	// Create a new group post like entry in your database.
// 	groupPostLike := &models.GroupPostLike{
// 		GroupPostLikeID: uuid.New(),
// 		GroupPostID:     groupPostID,
// 		LikeableID:      groupPostID,
// 		LikeableType:    "group_post",
// 		UserID:          userID,
// 		LikedAt:         time.Now(),
// 	}

// 	if err := db.DB.Create(groupPostLike).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to create group post like",
// 		})
// 	}

// 	// Update GroupPost fields
// 	groupPost.LikesCount++
// 	groupPost.Likers = append(groupPost.Likers, (groupPostLike.UserID.String()))
// 	groupPost.Likes = append(groupPost.Likes, *groupPostLike)

// 	// Save the updated GroupPost to the database
// 	result := db.DB.Save(&groupPost)
// 	if result.Error != nil {
// 		// Handle the error
// 		fmt.Printf("Failed to update GroupPost: %v\n", result.Error)
// 		return result.Error
// 	}
// 	postCreatorID := groupPost.UserID

// 	// Create a notification
// 	notification := &notifications.Notification{
// 		NotificationID: uuid.New(),
// 		RecipientID:    postCreatorID, // The user who created the post
// 		Message:        "You have a new like on your group post.",
// 		IsRead:         false,
// 		CreatedAt:      time.Now(),
// 		URL:            groupPost.URL,
// 	}

// 	// Save the notification in the database
// 	result = db.DB.Create(&notification)
// 	if result.Error != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to create notification",
// 		})
// 	}

// 	dbHandler := &db.DBHandlerImpl{
// 		DB: db.DB,
// 	}

// 	// Send a notification to the post creator
// 	notificationService := services.NewNotificationService(dbHandler)
// 	notificationService.SendNotification(postCreatorID, notification.Message, "like", groupPost.URL)

// 	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
// 		"message": "Group post like created successfully",
// 		"like":    groupPostLike,
// 	})
// }

// func ListGroupPostLikes(c *fiber.Ctx) error {
// 	// Parse the group post ID from the request.
// 	groupPostID := c.Params("groupPostID")

// 	// Query the database to get all likes for the specific group post.
// 	groupPostLikes := []models.GroupPostLike{}
// 	if err := db.DB.Where("group_post_id = ?", groupPostID).Find(&groupPostLikes).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to retrieve group post likes",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(groupPostLikes)
// }

// // CreateGroupPostCommentReply handles the creation of a group post comment reply.
// func CreateGroupPostCommentReply(c *fiber.Ctx) error {
// 	// Parse user ID from the request or any authentication method.
// 	userID, err := uuid.Parse(c.Locals("id").(string))
// 	if err != nil {
// 		return err
// 	}

// 	// Parse the comment ID from the request.
// 	commentIDParam := c.Params("commentID")
// 	commentID, err := uuid.Parse(commentIDParam)
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch group post comment
// 	groupPostComment := models.GroupPostComment{}

// 	if err := db.DB.Where("group_post_comment_id = ? ", commentID).First(&groupPostComment).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Failed to fetch group post comment details",
// 		})
// 	}
// 	// Parse the request body to get the content of the reply.
// 	var request struct {
// 		Content string `json:"content"`
// 	}
// 	if err := c.BodyParser(&request); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error": "Invalid request body",
// 		})
// 	}

// 	// Create a new group post comment reply.
// 	reply := models.GroupPostCommentReply{
// 		GroupPostCommentReplyID: uuid.New(),
// 		CommentID:               commentID,
// 		UserID:                  userID,
// 		Content:                 request.Content,
// 		CreatedAt:               time.Now(),
// 	}

// 	// Save the reply in the database.

// 	if err := db.DB.Create(&reply); err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to create group post comment reply",
// 		})
// 	}

// 	groupPostComment.Replies = append(groupPostComment.Replies, reply)

// 	if err := db.DB.Save(&groupPostComment).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to save reply to group post comment status",
// 		})
// 	}
// 	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
// 		"message": "Group post comment reply created successfully",
// 		"reply":   reply,
// 	})
// }

// // ViewGroupPostCommentReplies handles the retrieval of all replies for a group post comment.
// func ViewGroupPostCommentReplies(c *fiber.Ctx) error {
// 	// Parse the comment ID from the request.
// 	commentID, err := uuid.Parse(c.Params("commentID"))
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch all replies for the given comment from the database.
// 	replies := []models.GroupPostCommentReply{}
// 	if err := db.DB.Where("comment_id = ?", commentID).Find(&replies).Error; err != nil {
// 		// Handle the error (comment not found or database error).
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch comment replies",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"replies": replies,
// 	})
// }

// // hasPermissionToDeleteReply checks if the user has permission to delete the comment reply.
// func hasPermissionToDeleteReply(userID uuid.UUID, replyID uuid.UUID) bool {
// 	// Fetch the existing comment reply from the database.
// 	existingReply := models.GroupPostCommentReply{}
// 	if err := db.DB.Where("group_post_comment_reply_id = ?", replyID).First(&existingReply).Error; err != nil {
// 		// Handle the error (reply not found or database error).
// 		return false
// 	}

// 	// Check ownership: Allow deletion if the user is the author of the reply.
// 	return existingReply.UserID == userID
// }

// // UpdateGroupPostCommentReply handles the update of a group post comment reply.
// func UpdateGroupPostCommentReply(c *fiber.Ctx) error {
// 	// Parse the reply ID from the request.
// 	replyID, err := uuid.Parse(c.Params("replyID"))
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch the existing reply from the database.
// 	reply := models.GroupPostCommentReply{}
// 	if err := db.DB.Where("group_post_comment_reply_id = ?", replyID).First(&reply).Error; err != nil {
// 		// Handle the error (reply not found or database error).
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Reply not found",
// 		})
// 	}

// 	// Parse the updated content from the request body.
// 	update := new(models.GroupPostCommentReply)
// 	if err := c.BodyParser(update); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Invalid request body",
// 		})
// 	}

// 	// Update the reply content.
// 	reply.Content = update.Content

// 	// Save the updated reply to the database.
// 	if err := db.DB.Save(&reply).Error; err != nil {
// 		// Handle the error (database error).
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to update reply",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Reply updated successfully",
// 		"reply":   reply,
// 	})
// }

// func DeleteGroupPostCommentReply(c *fiber.Ctx) error {
// 	// Parse user ID from the request or any authentication method.
// 	userID, err := uuid.Parse(c.Locals("id").(string))
// 	if err != nil {
// 		return err
// 	}

// 	// Parse the comment reply ID from the request.
// 	replyID, err := uuid.Parse(c.Params("replyID"))
// 	if err != nil {
// 		return err
// 	}

// 	// Check if the user has permission to delete the comment reply.
// 	if !hasPermissionToDeleteReply(userID, replyID) {
// 		// If the user doesn't have permission, return a forbidden response.
// 		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Permission denied to delete the comment reply",
// 		})
// 	}

// 	// Fetch the existing comment reply from the database.
// 	existingReply := models.GroupPostCommentReply{}
// 	if err := db.DB.Where("group_post_comment_reply_id = ? AND user_id = ?", replyID, userID).First(&existingReply).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to fetch reply details",
// 		})
// 	}

// 	// Delete the comment reply from the database.
// 	if err := db.DB.Delete(&existingReply).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to delete reply",
// 		})
// 	}

// 	// Update the comment's reply count and remove the reply from the replies slice.
// 	if err := updateCommentAfterReplyDeletion(existingReply.CommentID); err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error": true,
// 			"input": "Failed to update comment after reply deletion",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message": "Group post comment reply deleted successfully",
// 	})
// }

// func updateCommentAfterReplyDeletion(commentID uuid.UUID) error {
// 	// Fetch the comment from the database.
// 	existingComment := models.GroupPostComment{}
// 	if err := db.DB.Where("group_post_comment_id = ?", commentID).First(&existingComment).Error; err != nil {
// 		return err
// 	}

// 	// Update the comment's reply count.
// 	existingComment.ReplyCount--

// 	// Save the updated comment in the database.
// 	if err := db.DB.Save(&existingComment).Error; err != nil {
// 		return err
// 	}

// 	return nil
// }

// func removeGroupPostCommentLike(likes []models.GroupPostCommentLike, likeToRemove models.GroupPostCommentLike) []models.GroupPostCommentLike {
// 	var updatedLikes []models.GroupPostCommentLike

// 	for _, like := range likes {
// 		// Check if the like matches the one to remove
// 		if like.GroupPostCommentLikeID != likeToRemove.GroupPostCommentLikeID {
// 			updatedLikes = append(updatedLikes, like)
// 		}
// 	}

// 	return updatedLikes
// }

// // CreateGroupPostCommentLike handles the creation of a like for a group post comment.
// func CreateGroupPostCommentLike(c *fiber.Ctx) error {
// 	// Parse user ID from the request or any authentication method.
// 	userID, err := uuid.Parse(c.Locals("id").(string))
// 	if err != nil {
// 		return err
// 	}

// 	// Parse the comment ID from the request.
// 	commentIDParam := c.Params("commentID")
// 	commentID, err := uuid.Parse(commentIDParam)
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch GroupPostComment

// 	groupPostComment := models.GroupPostComment{}
// 	if err := db.DB.Where("group_post_comment_id = ?", commentID).First(&groupPostComment).Error; err != nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error": "Failed to fetch group post comment details",
// 		})
// 	}
// 	// Check if the user has already liked the comment.
// 	existingLike := models.GroupPostCommentLike{}
// 	if err := db.DB.Where("likeable_id = ? AND user_id = ?", commentID, userID).First(&existingLike).Error; err == nil {
// 		// If a like entry already exists, the user has already liked the comment.

// 		groupPostComment.LikesCount--
// 		groupPostComment.Likes = removeGroupPostCommentLike(groupPostComment.Likes, existingLike)
// 		if err := db.DB.Save(&groupPostComment).Error; err != nil {
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 				"error": true,
// 				"input": "Failed to update like status",
// 			})
// 		}

// 		if err := db.DB.Where("likeable_id = ? AND user_id = ?", commentID, userID).Delete(&models.GroupPostCommentLike{}).Error; err != nil {
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 				"error":   true,
// 				"message": "Failed to delete group post like",
// 			})
// 		}
// 		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Your like has been removed from this comment",
// 		})
// 	}

// 	// Create a new group post comment like entry in the database.
// 	like := models.GroupPostCommentLike{
// 		GroupPostCommentLikeID: uuid.New(),
// 		LikeableID:             commentID,
// 		LikeableType:           "groupPost_comment",
// 		UserID:                 userID,
// 		CreatedAt:              time.Now(),
// 	}

// 	if err := db.DB.Create(&like).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to create group post comment like",
// 		})
// 	}

// 	// Update GroupPostComment fields
// 	groupPostComment.LikesCount++
// 	groupPostComment.Likes = append(groupPostComment.Likes, like)
// 	// Save the updated GroupPost to the database
// 	result := db.DB.Save(&groupPostComment)
// 	if result.Error != nil {
// 		// Handle the error
// 		fmt.Printf("Failed to update GroupPostComment: %v\n", result.Error)
// 		return result.Error
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
// 		"message": "Group post comment like created successfully",
// 		"like":    like,
// 	})
// }

// // ViewGroupPostCommentLikes handles the retrieval of all likes for a group post comment.
// func ViewGroupPostCommentLikes(c *fiber.Ctx) error {
// 	// Parse the comment ID from the request.
// 	commentID, err := uuid.Parse(c.Params("commentID"))
// 	if err != nil {
// 		return err
// 	}

// 	// Fetch all likes for the given comment from the database.
// 	likes := []models.GroupPostCommentLike{}
// 	if err := db.DB.Where("comment_id = ?", commentID).Find(&likes).Error; err != nil {
// 		// Handle the error (comment not found or database error).
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to fetch comment likes",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"likes": likes,
// 	})
// }

// func GetNotificationsHandler(c *fiber.Ctx) error {
// 	id := c.Params("id") // Assuming you extract the user ID from the request
// 	userID, err := StringToUUID(id)
// 	if err != nil {
// 		return err
// 	}

// 	user := new(models.User)
// 	if err := db.DB.Where("uuid = ?", userID).Find(&user).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"msg":   "failed to fetch post details",
// 			"error": err.Error(),
// 		})
// 	}
// 	if user == nil {
// 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "User not found",
// 		})
// 	}

// 	notifications, err := user.GetNotifications(db.DB)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":   true,
// 			"message": "Failed to get notifications",
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(notifications)
// }

// func SearchHandler(c *fiber.Ctx) error {
// 	searchType := c.Query("type")
// 	query := c.Query("query")

// 	switch searchType {
// 	case "user":
// 		// Handle user search
// 		users, err := SearchUsers(query)
// 		if err != nil {
// 			// Handle error
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 		}
// 		return c.JSON(fiber.Map{"results": users})

// 	case "message":
// 		// Handle message search
// 		messages, err := SearchMessages(query)
// 		if err != nil {
// 			// Handle error
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 		}
// 		return c.JSON(fiber.Map{"results": messages})

// 	default:
// 		// Handle unsupported search type
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Unsupported search type"})
// 	}
// }

// func SearchUsers(query string) ([]models.User, error) {
// 	var users []models.User

// 	query = strings.ToLower(query)
// 	// Query for users with matching first or last names
// 	result := db.DB.Where("url LIKE ?", "%"+query+"%").Find(&users)
// 	if result.Error != nil {
// 		return nil, result.Error
// 	}

// 	return users, nil
// }

// func SearchMessages(query string) ([]models.NormalMessage, error) {
// 	var messages []models.NormalMessage

// 	// Query messages where content contains the search query
// 	result := db.DB.Where("content LIKE ?", "%"+query+"%").Find(&messages)
// 	if result.Error != nil {
// 		return nil, result.Error
// 	}

// 	return messages, nil
// }

// func updateFollowerFollowingFields(followerID, followingID uuid.UUID) error {
// 	fmt.Println("inside updateFollowerFollowing")
// 	// Fetch the user being followed
// 	followingUser := GetUserByID(followingID)
// 	if followingUser == nil {
// 		return errors.New("user being followed not found")
// 	}

// 	// Update follower field in the user table for the user being followed
// 	followingUser.Followers = append(followingUser.Followers, GetUserByID(followerID).Followers...)
// 	if err := db.DB.Save(&followingUser).Error; err != nil {
// 		fmt.Println("Got error while updating Followers field")
// 		return err
// 	}

// 	// Fetch the follower
// 	followerUser := GetUserByID(followerID)
// 	if followerUser == nil {
// 		return errors.New("follower not found")
// 	}

// 	// Update following field in the user table for the follower
// 	followerUser.Following = append(followerUser.Following, GetUserByID(followingID).Following...)
// 	if err := db.DB.Save(&followerUser).Error; err != nil {
// 		fmt.Println("Got error while updating Following field")
// 		// Rollback the changes made to the Followers field
// 		followingUser.Followers = removeUserFromSlice(followingUser.Followers, followerID)
// 		db.DB.Save(&followingUser) // Save the changes to Followers field rollback
// 		return err
// 	}

// 	fmt.Println("follwer user ", followerUser)
// 	return nil
// }

// // Helper function to remove a user from a slice of users
// func removeUserFromSlice(users []models.User, userID uuid.UUID) []models.User {
// 	var updatedUsers []models.User
// 	for _, u := range users {
// 		if u.UUID != userID {
// 			updatedUsers = append(updatedUsers, u)
// 		}
// 	}
// 	return updatedUsers
// }

// func Follow(followerID, followingID uuid.UUID) error {
// 	follower := models.Follower{
// 		FollowerEntryID: uuid.New(),
// 		FollowerID:      followerID,
// 		UUID:            followingID, // Reverse the IDs for the Follower table
// 	}
// 	if err := db.DB.Create(&follower).Error; err != nil {
// 		return err
// 	}

// 	following := models.Following{
// 		FollowingEntryID: uuid.New(),
// 		UUID:             followerID,
// 		FollowingID:      followingID,
// 	}
// 	if err := db.DB.Create(&following).Error; err != nil {
// 		// If there's an error, you might want to handle it appropriately
// 		// and roll back the Follower entry.
// 		db.DB.Delete(&follower)
// 		return err
// 	}
// 	fmt.Println("Before executing updateFollowerFollowingFields funcion")
// 	// Update users in the database
// 	if err := updateFollowerFollowingFields(followerID, followingID); err != nil {
// 		// Handle the error appropriately
// 		return err
// 	}

// 	return nil
// }

// func Unfollow(followerID, followingID uuid.UUID) error {
// 	// Delete the entries from the Follower table
// 	if err := db.DB.Where("follower_id = ? AND uuid = ?", followerID, followingID).Delete(&models.Follower{}).Error; err != nil {
// 		return err
// 	}

// 	// Delete the entries from the Following table
// 	if err := db.DB.Where("uuid = ? AND following_id = ?", followerID, followingID).Delete(&models.Following{}).Error; err != nil {
// 		// Handle the error appropriately
// 		return err
// 	}

// 	return nil
// }

// func GetFollowers(userID uuid.UUID) ([]models.User, error) {
// 	var followers []models.Follower
// 	if err := db.DB.Where("uuid = ?", userID).Find(&followers).Error; err != nil {
// 		return nil, err
// 	}

// 	// Collect follower IDs
// 	var followerIDs []uuid.UUID
// 	for _, follower := range followers {
// 		followerIDs = append(followerIDs, follower.FollowerID)
// 	}

// 	// Fetch the follower details from the User table
// 	var followerDetails []models.User
// 	if err := db.DB.Where("uuid IN ?", followerIDs).Find(&followerDetails).Error; err != nil {
// 		return nil, err
// 	}

// 	return followerDetails, nil
// }

// func GetFollowing(userID uuid.UUID) ([]models.User, error) {
// 	var following []models.Following
// 	if err := db.DB.Where("uuid = ?", userID).Find(&following).Error; err != nil {
// 		return nil, err
// 	}

// 	// Collect following IDs
// 	var followingIDs []uuid.UUID
// 	for _, follow := range following {
// 		followingIDs = append(followingIDs, follow.FollowingID)
// 	}

// 	// Fetch the following details from the User table
// 	var followingDetails []models.User
// 	if err := db.DB.Where("uuid IN ?", followingIDs).Find(&followingDetails).Error; err != nil {
// 		return nil, err
// 	}

// 	return followingDetails, nil
// }

// // FollowHandler handles the request to follow a user.
// func FollowHandler(c *fiber.Ctx) error {
// 	userID := c.Params("userID")
// 	followerID := c.Params("followerID")

// 	if err := Follow(uuid.MustParse(userID), uuid.MustParse(followerID)); err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	return c.JSON(fiber.Map{"message": "User followed successfully"})
// }

// // UnfollowHandler handles the request to unfollow a user.
// func UnfollowHandler(c *fiber.Ctx) error {
// 	userID := c.Params("userID")
// 	followerID := c.Params("followerID")

// 	if err := Unfollow(uuid.MustParse(userID), uuid.MustParse(followerID)); err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	return c.JSON(fiber.Map{"message": "User unfollowed successfully"})
// }

// // GetFollowersHandler retrieves the followers for a given user ID.
// func GetFollowersHandler(c *fiber.Ctx) error {
// 	userID := c.Params("userID")
// 	followers, err := GetFollowers(uuid.MustParse(userID))
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	// You can customize the response format as needed
// 	return c.JSON(fiber.Map{"followers": followers})
// }

// // GetFollowingHandler retrieves the users that the given user is following.
// func GetFollowingHandler(c *fiber.Ctx) error {
// 	userID := c.Params("userID")
// 	following, err := GetFollowing(uuid.MustParse(userID))
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
// 	}

// 	// You can customize the response format as needed
// 	return c.JSON(fiber.Map{"following": following})
// }

// // VisitorDetails holds details of visitors
// type VisitorDetails struct {
// 	ID        uuid.UUID `json:"id"`
// 	Username  string    `json:"username"`
// 	Picture   string    `json:"picture"`
// 	Firstname string    `json:"firstname"`
// 	Lastname  string    `json:"lastname"`
// }

// // Handler function for handling user profile visits
// func VisitProfile(c *fiber.Ctx) error {
// 	// Get visitor user ID from request context or JWT token
// 	visitorID := c.Locals("id").(string)
// 	// Get profile user ID from request parameters
// 	profileUserID := c.Params("user_id")

// 	// Parse profile user ID into UUID format
// 	profileUserIDUUID, err := uuid.Parse(profileUserID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error": "Invalid user ID",
// 		})
// 	}

// 	// Query the database to fetch the profile user's data
// 	var profile models.User
// 	if err := db.DB.Where("uuid = ?", profileUserIDUUID).First(&profile).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error": "Profile not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":     "Database error",
// 			"error_msg": err.Error(),
// 		})
// 	}

// 	// Append the visitor's user ID to the visitors field
// 	profile.UserProfile.Visitors = append(profile.UserProfile.Visitors, visitorID)
// 	profile.UserProfile.UserID = profileUserIDUUID
// 	profile.UserProfile.Username = profile.Url
// 	profile.UserProfile.UserProfileID = uuid.New()
// 	// Save the updated profile data back to the database
// 	if err := db.DB.Save(&profile).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":     "Database error",
// 			"error_msg": err.Error(),
// 		})
// 	}

// 	// Query the database to fetch details of visitors
// 	var visitorsDetails []VisitorDetails
// 	if err := db.DB.Model(&models.User{}).Select("uuid", "url", "picture").Where("uuid = ?", visitorID).Scan(&visitorsDetails).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":     "Database error",
// 			"error_msg": err.Error(),
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"message":    "Profile visit recorded successfully",
// 		"visitors":   visitorsDetails,
// 		"profile_id": profileUserIDUUID,
// 	})
// }

// // Handler function to get the total count of visitors for a profile
// func GetVisitorCount(c *fiber.Ctx) error {
// 	// Get profile user ID from request parameters
// 	profileUserID := c.Params("user_id")

// 	// Parse profile user ID into UUID format
// 	profileUserIDUUID, err := uuid.Parse(profileUserID)
// 	if err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// 			"error": "Invalid user ID",
// 		})
// 	}

// 	// Query the database to fetch the profile user's data
// 	var profile models.UserProfile
// 	if err := db.DB.Where("user_id = ?", profileUserIDUUID).First(&profile).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 				"error": "Profile not found",
// 			})
// 		}
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 			"error":     "Database error",
// 			"error_msg": err.Error(),
// 		})
// 	}

// 	// Construct an array of VisitorDetails
// 	var visitorDetails []VisitorDetails
// 	for _, visitorID := range profile.Visitors {
// 		// Parse visitor ID into UUID format
// 		visitorUUID, err := uuid.Parse(visitorID)
// 		if err != nil {
// 			// Skip if visitor ID is invalid
// 			continue
// 		}
// 		// Query the database to fetch the visitor's data
// 		var visitor models.User
// 		if err := db.DB.Where("uuid = ?", visitorUUID).First(&visitor).Error; err != nil {
// 			// Skip if visitor not found
// 			continue
// 		}
// 		visitorDetails = append(visitorDetails, VisitorDetails{
// 			ID:        visitorUUID,
// 			Username:  visitor.Url,
// 			Picture:   visitor.Picture,
// 			Firstname: visitor.Firstname,
// 			Lastname:  visitor.Lastname,
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// 		"visitor_count": len(visitorDetails),
// 		"visitors":      visitorDetails,
// 	})
// }

// // Handler function to toggle user verification status
// // func ToggleUserVerification(c *fiber.Ctx) error {
// // 	// Parse request body to extract user_id
// // 	var requestBody struct {
// // 		UserID uuid.UUID `json:"user_id"`
// // 	}
// // 	if err := c.BodyParser(&requestBody); err != nil {
// // 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
// // 			"error": "Invalid request body",
// // 		})
// // 	}

// // 	// Retrieve user by user_id
// // 	user := GetUserByID(requestBody.UserID)
// // 	if user == nil {
// // 		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// // 			"error": "User not found",
// // 		})
// // 	}
// // 	fmt.Println("user dta", user)

// // 	// Toggle user verification status
// // 	user.Verified = !user.Verified

// // 	// Save user back to the database
// // 	if err := db.DB.Save(&user).Error; err != nil {
// // 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// // 			"error":     "Database error",
// // 			"error_msg": err.Error(),
// // 		})
// // 	}

// // 	return c.Status(fiber.StatusOK).JSON(fiber.Map{
// // 		"message":  "User verification status toggled successfully",
// // 		"user_id":  user.UUID,
// // 		"verified": user.Verified,
// // 	})
// // }

package controllers

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	db "github.com/RohitKMishra/IamverseDemo/database"
	"github.com/RohitKMishra/IamverseDemo/models"
	"github.com/gofiber/fiber/v2"
	uuid "github.com/google/uuid"
	"github.com/lib/pq"
	// "github.com/RohitKMishra/codeapto-backend-go/services"
	"gorm.io/gorm"
)

type ReposterResponsePost struct {
	PostID               uuid.UUID
	PostUserID           uuid.UUID
	PostTitle            string
	PostContent          string
	PostImage            string
	PostVideo            string
	PostURL              string
	UserPostVisibilities []models.UserPostVisibility
	Dislikes             int
	Likers               pq.StringArray
	Dislikers            pq.StringArray
	Comments             []models.Comment
	Likes                []models.Like
	LikesCount           int
	CommentCount         int
	// Hashtags             []models.Hashtag
	Mentions        pq.StringArray
	TaggedUserIDs   pq.StringArray
	EmojiReactions  []models.EmojiReaction
	UserReaction    models.UserReaction
	CelebrateCount  int
	SupportCount    int
	LoveCount       int
	InsightfulCount int
	FunnyCount      int
	LikeEmojiCount  int
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Reposts         []models.Repost
	RepostersData   map[string]models.User
}

type PostWithReposters struct {
	ReposterResponsePost ReposterResponsePost     `json:"post"`
	RepostersData        (map[string]models.User) `json:"reposters"`
}

type PostJSON struct {
	PostUserID     uuid.UUID         `json:"post_user_id"`
	PostTitle      string            `json:"post_title"`
	PostContent    string            `json:"post_content"`
	PostImage      string            `json:"post_image"`
	PostVideo      string            `json:"post_video"`
	PostURL        string            `json:"post_url"`
	UserVisibility map[string]string `json:"user_visibility"`
	Dislikes       int               `json:"dislikes"`
	Likers         pq.StringArray    `gorm:"type:text[]" json:"likers"`
	Dislikers      pq.StringArray    `gorm:"type:uuid[]" json:"dislikers"`
	Comments       []models.Comment  ` json:"comments"`
	Likes          []models.Like     `json:"likes"`
	LikesCount     int               `json:"likes_count"`
	CommentCount   int               `json:"comment_count"`
	TaggedUserIDs  pq.StringArray    `json:"tagged_user_ids"`
	// Add other fields from the Post struct as needed
	Hashtags  []string       `json:"hashtags"`
	Mentions  pq.StringArray `gorm:"type:text[]" json:"mentions"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func ConvertToPost(postJSON PostJSON, postUserID uuid.UUID) models.Post {
	hashtags := make([]models.Hashtag, len(postJSON.Hashtags))
	for i, hashtagName := range postJSON.Hashtags {
		// Check if the hashtag already exists
		var existingHashtag models.Hashtag
		if err := db.DB.Where("name = ?", hashtagName).First(&existingHashtag).Error; err != nil {
			// If the hashtag doesn't exist, create a new one with a new UUID
			if errors.Is(err, gorm.ErrRecordNotFound) {
				newHashtag := models.Hashtag{
					HashtagID: uuid.New(),
					Name:      hashtagName,
				}

				// Save the new hashtag to the database
				if err := db.DB.Create(&newHashtag).Error; err != nil {
					// Handle the error as needed
					fmt.Printf("Error creating new hashtag: %v\n", err)
					return models.Post{}
				}

				hashtags[i] = newHashtag
			} else {
				// Handle other errors
				// You may want to log the error or handle it based on your requirements
				fmt.Printf("Error retrieving existing hashtag: %v\n", err)
				// You can choose to return an empty Post or handle the error in another way
				return models.Post{}
			}
		} else {
			// If the hashtag exists, reuse its ID
			hashtags[i] = existingHashtag
		}
	}

	return models.Post{
		PostID:        uuid.New(),
		PostUserID:    postUserID,
		PostTitle:     postJSON.PostTitle,
		PostContent:   postJSON.PostContent,
		PostImage:     postJSON.PostImage,
		PostVideo:     postJSON.PostVideo,
		PostURL:       postJSON.PostURL,
		Likes:         postJSON.Likes,
		Likers:        postJSON.Likers,
		Dislikes:      postJSON.Dislikes,
		Dislikers:     postJSON.Dislikers,
		TaggedUserIDs: postJSON.TaggedUserIDs,
		Hashtags:      hashtags,
		Mentions:      postJSON.Mentions,
		LikesCount:    postJSON.LikesCount,
		CommentCount:  postJSON.CommentCount,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// generateUniqueURL generates a unique URL based on the first three words of the input string
func generateUniqueURL(title string, currentPostID uuid.UUID) string {
	// Extract the first three words from the title
	words := strings.Fields(title)
	var truncatedWords []string
	if len(words) > 3 {
		truncatedWords = words[:3]
	} else {
		truncatedWords = words
	}

	// Combine the truncated words with hyphens
	url := strings.Join(truncatedWords, "-")
	url = strings.ToLower(url)
	// Check if the URL is already taken, and if so, append a random string
	uniqueURL := url
	for {
		if isURLTaken(uniqueURL, currentPostID) {
			uniqueURL = url + "-" + generateRandomString(4)
		} else {
			break
		}
	}
	return uniqueURL
}

// isURLTaken checks if the given URL is already taken, excluding the current post
func isURLTaken(url string, currentPostID uuid.UUID) bool {
	var count int64
	db.DB.Model(&models.Post{}).Where("post_url = ? AND post_id != ?", url, currentPostID).Count(&count)
	return count > 0
}

// GetLikeStatus checks if a user has already liked an entity (post or comment).
func GetLikeStatus(userID uuid.UUID, likeableID uuid.UUID, likeableType string) (bool, *models.Like) {
	var like models.Like
	result := db.DB.
		Where("user_id = ? AND likeable_id = ? AND likeable_type = ?", userID, likeableID, likeableType).
		First(&like)

	return result.Error == nil, &like
}

// removeFromArray removes an element from a pq.StringArray.
func removeFromArray(arr pq.StringArray, elem uuid.UUID) pq.StringArray {
	var result pq.StringArray
	for _, v := range arr {
		if v != elem.String() {
			result = append(result, v)
		}
	}
	return result
}

func GetRepliesForPost(postID uuid.UUID) ([]models.Comment, error) {
	var replies []models.Comment
	if err := db.DB.Where("post_id = ? AND parent_id IS NOT NULL", postID).Find(&replies).Error; err != nil {
		return nil, err
	}
	return replies, nil
}

func extractHashtags(content string) []string {
	// Use a regular expression to find hashtags
	// This is a simple example and might need adjustment based on your requirements
	regex := regexp.MustCompile(`#(\w+)`)
	matches := regex.FindAllStringSubmatch(content, -1)

	// Extract the captured groups (hashtags) and ensure uniqueness
	uniqueHashtags := make(map[string]bool)
	for _, match := range matches {
		// Ensure case-insensitive uniqueness
		uniqueHashtags[strings.ToLower(match[1])] = true
	}

	// Convert unique hashtags to a slice
	var hashtags []string
	for hashtag := range uniqueHashtags {
		hashtags = append(hashtags, hashtag)
	}

	return hashtags
}

func cleanUUIDString(idStr string) string {
	// Remove any non-printable characters or whitespace
	cleanedStr := strings.TrimSpace(idStr)
	return cleanedStr
}

func CreatePost(c *fiber.Ctx) error {
	id := c.Locals("id").(string)
	postUserID, err := StringToUUID(id)
	if err != nil {
		return err
	}
	postJSON := new(PostJSON)
	if err := c.BodyParser(&postJSON); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Convert PostJSON to Post
	post := ConvertToPost(*postJSON, postUserID)
	postID := uuid.New()

	// Generate a unique URL based on the first three words of the post title
	url := generateUniqueURL(post.PostContent, post.PostID)
	post.PostURL = url

	// Regular expression to match mentions or tags in the updated post content
	mentionRegex := regexp.MustCompile(`@(\w+)`)

	// Find all matches in the updated post content
	matches := mentionRegex.FindAllStringSubmatch(post.PostContent, -1)

	taggedUserIDs := make(pq.StringArray, len(matches))

	for i, match := range matches {
		if len(match) == 2 {
			parsedUserID, err := uuid.Parse(match[1])
			if err == nil {
				taggedUserIDs[i] = parsedUserID.String()
			}
		}
	}

	// Handle existence of tagged users
	var taggedUserIDsExUser []uuid.UUID
	if post.TaggedUserIDs != nil {
		existingUsers := make([]models.User, 0)

		for _, idStr := range post.TaggedUserIDs {
			cleanedIDStr := cleanUUIDString(idStr)
			parsedID, err := uuid.Parse(cleanedIDStr)
			if err != nil {
				return err
			}
			taggedUserIDsExUser = append(taggedUserIDsExUser, parsedID)
		}

		if err := db.DB.Where("uuid IN ?", taggedUserIDsExUser).Find(&existingUsers).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error":     "Database error",
				"error_msg": err.Error(),
			})
		}

		// Check if all tagged users exist
		for _, userID := range post.TaggedUserIDs {
			userExists := false
			// Manual check by iterating over existing users
			for _, existingUser := range existingUsers {
				if existingUser.UUID.String() == userID {
					userExists = true
					break
				}
			}
			if !userExists {
				return c.Status(400).JSON(fiber.Map{
					"error":   true,
					"message": "One or more tagged users do not exist",
				})
			}
		}
	}

	tx := db.DB.Begin()

	// Extract hashtags
	hashtags := extractHashtags(post.PostContent)

	// Ensure unique hashtags before association
	uniqueHashtags := make(map[string]bool)
	for _, hashtagName := range hashtags {
		uniqueHashtags[hashtagName] = true
	}

	// Create or update associated hashtags
	for hashtagName := range uniqueHashtags {
		var hashtag models.Hashtag
		if err := db.DB.Where("name = ?", hashtagName).First(&hashtag).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				newHashtag := models.Hashtag{
					HashtagID: uuid.New(),
					Name:      hashtagName,
				}
				if err := db.DB.Create(&newHashtag).Error; err != nil {
					return err
				}
				post.Hashtags = append(post.Hashtags, newHashtag)
			} else {
				return err
			}
		} else {
			post.Hashtags = append(post.Hashtags, hashtag)
		}
	}

	// Create the post
	post = models.Post{
		PostID:        postID,
		PostUserID:    postUserID,
		PostTitle:     post.PostTitle,
		PostContent:   post.PostContent,
		PostImage:     post.PostImage,
		PostVideo:     post.PostVideo,
		PostURL:       post.PostURL,
		Likes:         post.Likes,
		Likers:        post.Likers,
		Dislikes:      post.Dislikes,
		Dislikers:     post.Dislikers,
		Hashtags:      post.Hashtags,
		Mentions:      post.Mentions,
		LikesCount:    post.LikesCount,
		CommentCount:  post.CommentCount,
		TaggedUserIDs: taggedUserIDs,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Create UserPostVisibility
	userPostVisibility := models.UserPostVisibility{
		UserPostVisibilityID: uuid.New(),
		PostVisibilityUserID: post.PostUserID,
		PostID:               post.PostID,
		Visible:              true, // Set default visibility
	}

	// Save post and user post visibility
	if err := tx.Create(&post).Error; err != nil {
		tx.Rollback()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to create post",
		})
	}
	if err := tx.Create(&userPostVisibility).Error; err != nil {
		tx.Rollback()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to create user post visibility",
		})
	}

	// Commit the transaction
	tx.Commit()

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Post created successfully",
		"post":    post,
	})
}

func GetPosts(c *fiber.Ctx) error {
	id := c.Locals("id")
	allPosts := []models.Post{}

	if err := db.DB.Where("post_user_id = ? ", id).Find(&allPosts).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch post details",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"Posts": allPosts,
	})
}

// Function to toggle post visibility for a user
func TogglePostVisibility(postID, userID string, visible bool) error {
	// Convert IDs to UUID
	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	postIDUUID, err := uuid.Parse(postID)
	if err != nil {
		return err
	}

	// Check if visibility setting already exists
	var visibility models.UserPostVisibility
	result := db.DB.Where("post_visibility_user_id = ? AND post_id = ?", userIDUUID, postIDUUID).First(&visibility)
	if result.Error != nil {
		// Create new visibility setting if not found
		visibility = models.UserPostVisibility{
			UserPostVisibilityID: uuid.New(),
			PostVisibilityUserID: userIDUUID,
			PostID:               postIDUUID,
			Visible:              visible,
		}
		if err := db.DB.Create(&visibility).Error; err != nil {
			return err
		}
	} else {
		// Update existing visibility setting
		visibility.Visible = visible
		if err := db.DB.Save(&visibility).Error; err != nil {
			return err
		}
	}

	return nil
}

// Define a new function that accepts a Fiber context and calls TogglePostVisibility
func TogglePostVisibilityHandler(c *fiber.Ctx) error {
	// Check if the request body is empty
	if len(c.Body()) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Empty request body",
		})
	}

	// Parse request body to get the visibility data
	visibility := new(models.UserPostVisibility)
	if err := c.BodyParser(visibility); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	fmt.Println("Visibility body", visibility)

	// Call TogglePostVisibility function
	if err := TogglePostVisibility(visibility.PostID.String(), visibility.PostVisibilityUserID.String(), visibility.Visible); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Return success response
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Post visibility toggled successfully",
	})
}

// GetAllPostsHandler retrieves all posts visible to the current user
func GetAllPostsHandler(c *fiber.Ctx) error {
	// Get the user ID from the request context
	userID := c.Locals("id").(string)

	// Fetch visible posts for the user
	posts, err := GetVisiblePosts(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Return the visible posts with reposters data
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"posts": posts,
	})
}

// Define a struct to hold user data
type UserData struct {
	// Define fields of user data you want to include
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	// Add more fields as needed
}

// GetVisiblePosts retrieves posts visible to a specific user
func GetVisiblePosts(userID string) ([]models.Post, error) {
	var posts []models.Post
	// Convert user ID to UUID
	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	// Fetch visible posts for the user
	if err := db.DB.Preload("Reposts").Where("post_user_id = ?", userIDUUID).Find(&posts).Error; err != nil {
		return nil, err
	}

	return posts, nil
}

func GetAllPosts(c *fiber.Ctx) error {
	// Extract user ID from the context
	// userID := c.Locals("id").(string)

	// Get all posts from the database
	allPosts := []models.Post{}
	if err := db.DB.Find(&allPosts).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch post details",
		})
	}

	// Filter posts based on visibility settings for the current user
	visiblePosts := make([]models.Post, 0)
	// for _, post := range allPosts {
	// 	// Check if the post is visible to the current user
	// 	// if isVisibleToUser(post, userID) {
	// 	// 	visiblePosts = append(visiblePosts, post)
	// 	// }
	// }

	// Return the filtered posts
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"Posts": visiblePosts,
	})
}

func GetPost(c *fiber.Ctx) error {
	postID := c.Params("id")
	fmt.Println("post id from params", postID)

	post := &models.Post{}

	if err := db.DB.Where("post_id = ?", postID).Find(&post).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch post details",
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"post": post,
	})
}

func GetPostByURL(c *fiber.Ctx) error {
	postURL := c.Params("url")
	fmt.Println("post id from params", postURL)

	post := &models.Post{}

	if err := db.DB.Where("post_url = ?", postURL).Find(&post).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch post details",
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"post": post,
	})
}
func UpdatePost(c *fiber.Ctx) error {
	postID := c.Params("id")
	userID := c.Locals("id").(string)

	var post models.Post
	if err := db.DB.Where("post_id = ? AND post_user_id = ?", postID, userID).First(&post).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{"error": "Post not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	var updateData struct {
		PostTitle   *string `json:"post_title"`
		PostContent *string `json:"post_content"`
		PostImage   *string `json:"post_image"`
		PostVideo   *string `json:"post_video"`

		TaggedUserIDs pq.StringArray   `json:"tagged_user_ids"`
		Hasgtags      []models.Hashtag `json:"hashtags"`
	}

	if err := c.BodyParser(&updateData); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": err.Error(),
			"input": "Please review your input",
		})
	}

	// Handle existence of tagged users
	if updateData.TaggedUserIDs != nil {
		existingUsers := make([]models.User, 0)
		if err := db.DB.Where("uuid IN ?", updateData.TaggedUserIDs).Find(&existingUsers).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database error"})
		}

		// Check if all tagged users exist
		for _, userID := range updateData.TaggedUserIDs {
			userExists := false
			for _, existingUser := range existingUsers {
				if existingUser.UUID == uuid.MustParse(userID) {
					userExists = true
					break
				}
			}

			if !userExists {
				return c.Status(400).JSON(fiber.Map{
					"error":   true,
					"message": "One or more tagged users do not exist",
				})
			}
			dbHandler := &db.DBHandlerImpl{DB: db.DB}

			// Send notification to each tagged user
			notificationService := services.NewNotificationService(dbHandler)
			notificationMessage := fmt.Sprintf("You have been tagged in a post: %s", post.PostTitle)
			notificationService.SendNotification(uuid.MustParse(userID), notificationMessage, "tagged_in_post", post.PostURL)
		}

		// All tagged users exist, update the Post struct
		post.TaggedUserIDs = updateData.TaggedUserIDs
	}

	if updateData.PostTitle != nil {
		post.PostTitle = *updateData.PostTitle
	}
	if updateData.PostContent != nil {
		post.PostContent = *updateData.PostContent
	}
	if updateData.PostImage != nil {
		post.PostImage = *updateData.PostImage
	}
	if updateData.PostVideo != nil {
		post.PostTitle = *updateData.PostVideo
	}
	if updateData.Hasgtags != nil {
		post.Hashtags = updateData.Hasgtags
	}

	// Update the post with the merged data
	if err := db.DB.Save(&post).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update posts table",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Post updated successfully",
		"post":    post,
	})
}

func DeletePost(c *fiber.Ctx) error {
	postID := c.Params("id")

	if err := db.DB.Where("post_id = ?", postID).Delete(&models.Post{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Post deletion failed",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Post deleted successfully",
	})

}

// CreateComment handler
func CreateComment(c *fiber.Ctx) error {
	id := c.Locals("id").(string)
	id1, err := StringToUUID(id)
	if err != nil {
		return err
	}

	comment := new(models.Comment)
	if err := c.BodyParser(comment); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"input": "Please review your input",
		})
	}

	comment = &models.Comment{
		CommentID: uuid.New(),
		UserID:    id1,
		Content:   comment.Content,
		PostID:    comment.PostID,
		Likes:     nil, // Initialize likes to an empty array
		LikeCount: 0,   // Initialize like count to 0
		Replies:   nil, // Initialize replies to an empty array
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := db.DB.Create(&comment)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to create comment",
		})
	}

	// Increment the commentCount in the Post model
	if err := db.DB.Model(&models.Post{}).Where("post_id = ?", comment.PostID).UpdateColumn("comment_count", gorm.Expr("comment_count + 1")).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update comment count",
		})
	}

	// Fetch the user ID of the post creator
	postCreator := models.Post{}
	if err := db.DB.Where("post_id = ?", comment.PostID).Find(&postCreator).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Failed to fetch post details",
		})
	}
	postCreatorID := postCreator.PostUserID
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to get post creator",
		})
	}

	// Send a notification to the post creator
	dbHandler := &db.DBHandlerImpl{DB: db.DB}

	if postCreatorID != uuid.Nil {
		notificationService := services.NewNotificationService(dbHandler)
		notificationMessage := fmt.Sprintf("You have a new comment on your post: %s", comment.Content)
		notificationService.SendNotification(postCreatorID, notificationMessage, "comment", postCreator.PostURL)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Comment created successfully",
		"comment": comment,
	})
}

// get commentID from url

func GetCommentByCommentID(c *fiber.Ctx) error {
	commentID := uuid.MustParse(c.Params("commentID"))

	comment := []models.Comment{}
	if err := db.DB.Preload("Likes").Preload("Replies").Where("comment_id = ?", commentID).Find(&comment).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Comment not found",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"comment": comment,
	})
}
func GetCommentByPostID(c *fiber.Ctx) error {
	postID := uuid.MustParse(c.Params("postID"))
	commentDetails := []models.Comment{}
	if err := db.DB.Where("post_id = ?", postID).Preload("Likes").Find(&commentDetails).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Failed to fetch comment details",
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"comment": commentDetails,
	})
}

func UpdateComment(c *fiber.Ctx) error {
	id := c.Params("id")
	commentID, err := StringToUUID(id)
	if err != nil {
		return err
	}

	fmt.Println("comment id", commentID)
	var comment models.Comment
	if err := db.DB.First(&comment, commentID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Comment not found"})
	}
	// Update the comment with new data
	if err := c.BodyParser(&comment); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := db.DB.Save(&comment).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(comment)
}

func DeleteComment(c *fiber.Ctx) error {
	id := c.Params("id")
	commentID, err := StringToUUID(id)
	if err != nil {
		return err
	}
	var comment models.Comment
	if err := db.DB.First(&comment, commentID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Comment not found"})
	}
	if err := db.DB.Delete(&comment).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Decrement the commentCount in the Post model
	if err := db.DB.Model(&models.Post{}).Where("post_id = ?", comment.PostID).UpdateColumn("comment_count", gorm.Expr("comment_count - 1")).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update comment count",
		})
	}
	return c.JSON(fiber.Map{
		"message": "Reply deleted successfully",
	})

}

// CreateEmojiHandler creates a new emoji record
func CreateEmojiHandler(c *fiber.Ctx) error {
	// Parse the request body into an Emoji struct
	emoji := new(models.Emoji)
	if err := c.BodyParser(emoji); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Generate a UUID for the new emoji
	emoji.EmojiID = uuid.New()

	// Save the emoji record to the database
	if err := db.DB.Create(&emoji).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create emoji",
		})
	}

	// Return a success response with the created emoji
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Emoji created successfully",
		"emoji":   emoji,
	})
}

func GetUserReactionByPostID(c *fiber.Ctx) error {

	type NewPost struct {
		PostID          uuid.UUID              `gorm:"primaryKey" json:"post_id"`
		PostUserID      uuid.UUID              `json:"post_user_id"`
		PostTitle       string                 `json:"post_title"`
		PostContent     string                 `json:"post_content"`
		PostImage       string                 `json:"post_image"`
		PostVideo       string                 `json:"post_video"`
		PostURL         string                 `json:"post_url"`
		Dislikes        int                    `json:"dislikes"`
		Likers          pq.StringArray         `json:"likers"`
		Dislikers       pq.StringArray         `json:"dislikers"`
		Comments        []models.Comment       `json:"comments"`
		Likes           []models.Like          `json:"likes"`
		LikesCount      int                    `json:"likes_count"`
		CommentCount    int                    `json:"comment_count"`
		Hashtags        []models.Hashtag       `json:"hashtags"`
		Mentions        pq.StringArray         `json:"mentions"`
		TaggedUserIDs   pq.StringArray         `json:"tagged_user_ids"`
		EmojiReactions  []models.EmojiReaction ` json:"emoji_reactions"`
		UserReaction    models.UserReaction    `json:"user_reaction"`
		CelebrateCount  int                    `json:"celebrate_count"`
		SupportCount    int                    `json:"support_count"`
		LoveCount       int                    `json:"love_count"`
		InsightfulCount int                    `json:"insightful_count"`
		FunnyCount      int                    `json:"funny_count"`
		LikeEmojiCount  int                    `json:"like_emoji_count"`
		CreatedAt       time.Time              `json:"created_at"`
		UpdatedAt       time.Time              `json:"updated_at"`
	}
	// Extract post ID from request parameters
	postID := c.Params("postID")

	// Query the database to find the post with the given ID
	userResponse := models.UserReaction{}
	if err := db.DB.Where("post_id = ?", postID).First(&userResponse).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Post not found",
		})
	}

	// Extract post data using post id and add the reaction user data to it. Send it as a response

	post := models.Post{}
	if err := db.DB.Where("post_id = ?", postID).First(&post).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Post not found",
		})
	}

	newPost := NewPost{
		PostID:          post.PostID,
		PostUserID:      post.PostUserID,
		PostTitle:       post.PostTitle,
		PostContent:     post.PostContent,
		PostImage:       post.PostImage,
		PostVideo:       post.PostVideo,
		Dislikes:        post.Dislikes,
		Dislikers:       post.Dislikers,
		Likes:           post.Likes,
		Likers:          post.Likers,
		Comments:        post.Comments,
		LikesCount:      post.LikesCount,
		CommentCount:    post.CommentCount,
		Hashtags:        post.Hashtags,
		Mentions:        post.Mentions,
		TaggedUserIDs:   post.TaggedUserIDs,
		EmojiReactions:  post.EmojiReactions,
		UserReaction:    userResponse,
		CelebrateCount:  post.CelebrateCount,
		SupportCount:    post.SupportCount,
		LoveCount:       post.LoveCount,
		InsightfulCount: post.InsightfulCount,
		FunnyCount:      post.FunnyCount,
		LikeEmojiCount:  post.LikeEmojiCount,
		CreatedAt:       post.CreatedAt,
		UpdatedAt:       post.UpdatedAt,
	}
	// Return the user reaction data as a response
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"post": newPost,
	})
}

func GetEmojiDetailsByReactionName(c *fiber.Ctx) error {
	// Get the reaction name from the URL parameters
	reactionName := c.Params("reactionName")

	// Query the database to fetch the emoji details by reaction name
	emoji := models.Emoji{}
	if err := db.DB.Where("name = ?", reactionName).First(&emoji).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Emoji not found for the specified reaction name",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch emoji details",
		})
	}

	// Respond with the emoji details
	return c.Status(fiber.StatusOK).JSON(emoji)
}

func LikePost(c *fiber.Ctx) error {
	// Parse request body to get the like data
	like := new(models.Like)
	if err := c.BodyParser(like); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"input": "Please review your input",
		})
	}

	// Extract user ID from context
	userID, _ := uuid.Parse(c.Locals("id").(string))

	// Fetch the post
	post := models.Post{}
	if err := db.DB.Where("post_id = ?", like.LikeableID).First(&post).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Post not found",
		})
	}

	// Check if the user has already liked the post
	existingLike := &models.Like{}
	result := db.DB.Where("user_id = ? AND likeable_id = ? AND likeable_type = ?", userID, like.LikeableID, "post").First(existingLike)
	if result.RowsAffected > 0 {
		// User has already liked the post, so delete the like
		if err := db.DB.Delete(existingLike).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to delete like",
			})
		}

		// Decrement corresponding reaction count based on existingLike emoji
		switch existingLike.Emoji.Name {
		case "celebrate":
			post.CelebrateCount--
		case "support":
			post.SupportCount--
		case "love":
			post.LoveCount--
		case "insightful":
			post.InsightfulCount--
		case "funny":
			post.FunnyCount--
		case "like":
			post.LikeEmojiCount--
		}

		post.LikesCount--
		// Remove user from likers array
		for i, liker := range post.Likers {
			if liker == userID.String() {
				post.Likers = append(post.Likers[:i], post.Likers[i+1:]...)
				break
			}
		}

		// Set UserReaction field of Post struct to empty
		post.UserReaction = models.UserReaction{}

		// Delete corresponding entry from the UserReaction table
		if err := db.DB.Where("post_id = ? AND user_id = ?", post.PostID, userID).Delete(&models.UserReaction{}).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to delete user reaction",
			})
		}

		// Save the updated post data after removing like
		if err := db.DB.Save(&post).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to update post",
			})
		}
	} else {
		// User is liking the post for the first time
		like.LikeID = uuid.New()
		like.UserID = userID
		like.CreatedAt = time.Now()

		// Create the like
		if err := db.DB.Create(&like).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to create like",
			})
		}

		// Increment corresponding reaction count based on like emoji
		switch like.Emoji.Name {
		case "celebrate":
			post.CelebrateCount++
		case "support":
			post.SupportCount++
		case "love":
			post.LoveCount++
		case "insightful":
			post.InsightfulCount++
		case "funny":
			post.FunnyCount++
		case "like":
			post.LikeEmojiCount++
		}

		// Add user to likers array
		post.LikesCount++
		post.Likers = append(post.Likers, userID.String())

		// Update UserReaction field of Post struct
		post.UserReaction = models.UserReaction{
			UserID:       userID,
			PostID:       post.PostID,
			ReactionName: like.Emoji.Name,
		}

		// Create a new entry in UserReaction table
		userReaction := models.UserReaction{
			UserID:       userID,
			PostID:       post.PostID,
			ReactionName: like.Emoji.Name,
		}
		if err := db.DB.Create(&userReaction).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to create user reaction",
			})
		}

	}

	// Save the updated post data
	if err := db.DB.Save(&post).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update post",
		})
	}

	// Send a notification to the user
	dbHandler := &db.DBHandlerImpl{DB: db.DB}
	notificationService := services.NewNotificationService(dbHandler)
	notificationMessage := fmt.Sprintf("Your like status has been updated on post")
	notificationService.SendNotification(userID, notificationMessage, "like", post.PostURL)

	// Send response
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Like status updated successfully for post",
		"like":    like,
	})
}

// LikeComment handles liking or unliking a comment.
func LikeComment(c *fiber.Ctx) error {
	id := c.Locals("id").(string)
	userID, _ := uuid.Parse(id)
	like := new(models.Like)

	if err := c.BodyParser(like); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"input": "Please review your input",
		})
	}

	// Check if the user has already liked the comment
	existingLike := &models.Like{}
	result := db.DB.Where("user_id = ? AND likeable_id = ? AND likeable_type = ?", userID, like.LikeableID, "comment").First(existingLike)

	if result.RowsAffected > 0 {
		// User has already liked the comment
		if existingLike.LikeStatus == like.LikeStatus {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": true,
				"input": "You have already submitted this like status for the comment",
			})
		}

		// Update the existing like status
		existingLike.LikeStatus = like.LikeStatus
		existingLike.CreatedAt = time.Now()
		result := db.DB.Save(&existingLike)
		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to update like status",
			})
		}
		like.LikeID = existingLike.LikeID
	} else {
		// User is liking the comment for the first time
		like = &models.Like{
			LikeID:       uuid.New(),
			UserID:       userID,
			LikeableID:   like.LikeableID,
			LikeableType: "comment",
			LikeStatus:   like.LikeStatus,
			Emoji:        like.Emoji,
			CreatedAt:    time.Now(),
		}

		result := db.DB.Create(&like)
		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": true,
				"input": "Failed to update like status",
			})
		}
	}

	// Update likers and like count in the comment
	comment := models.Comment{}
	if err := db.DB.Where("comment_id = ?", like.LikeableID).First(&comment).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Comment not found",
		})
	}

	// Get post on which the comment is made
	post := models.Post{}
	if err := db.DB.Where("post_id = ?", comment.PostID).First(&post).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error msg": "Post not found",
			"error":     err,
		})
	}

	if like.LikeStatus {
		comment.Likers = append(comment.Likers, userID.String())
		comment.LikeCount++
	} else {
		comment.Likers = removeFromArray(comment.Likers, userID)
		comment.LikeCount--
	}

	if err := db.DB.Save(&comment).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update comment likes",
		})
	}

	// Send a notification to the user
	dbHandler := &db.DBHandlerImpl{DB: db.DB}

	notificationService := services.NewNotificationService(dbHandler)
	notificationMessage := fmt.Sprintf("Your like status has been updated on comment")
	notificationService.SendNotification(userID, notificationMessage, "like", post.PostURL)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Like status updated successfully for comment",
		"like":    like,
	})
}

// GetLikePost handler to fetch all likes for a post
func GetLikePost(c *fiber.Ctx) error {
	postID := c.Params("postID")
	var likes []models.Like
	result := db.DB.Where("likeable_id = ? AND likeable_type = 'post'", postID).Find(&likes)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to fetch likes for the post",
		})
	}

	return c.JSON(fiber.Map{
		"likes":   likes,
		"message": "Likes for the post fetched successfully",
	})
}

// GetLikeComment handler to fetch all likes for a comment
func GetLikeComment(c *fiber.Ctx) error {
	commentID := c.Params("commentID")
	var likes []models.Like
	result := db.DB.Where("likeable_id = ? AND likeable_type = 'comment'", commentID).Find(&likes)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to fetch likes for the comment",
		})
	}

	return c.JSON(fiber.Map{
		"likes":   likes,
		"message": "Likes for the comment fetched successfully",
	})
}

func CreateReply(c *fiber.Ctx) error {
	id := c.Locals("id").(string)
	id1, err := StringToUUID(id)
	if err != nil {
		return err
	}

	reply := new(models.Reply)
	if err := c.BodyParser(reply); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"input": "Please review your input",
		})
	}

	reply = &models.Reply{
		ReplyID:   uuid.New(),
		UserID:    id1,
		Content:   reply.Content,
		CommentID: reply.CommentID,
		Likes:     nil, // Initialize likes to an empty array
		LikeCount: 0,   // Initialize like count to 0
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := db.DB.Create(&reply)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to create reply",
		})
	}

	// Increment the replyCount in the Comment model
	if err := db.DB.Model(&models.Comment{}).Where("comment_id = ?", reply.CommentID).UpdateColumn("reply_count", gorm.Expr("reply_count + 1")).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update reply count",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Reply created successfully",
		"reply":   reply,
	})
}

func UpdateReply(c *fiber.Ctx) error {
	id := c.Params("id")
	replyID, err := StringToUUID(id)
	if err != nil {
		return err
	}

	var reply models.Reply
	if err := db.DB.First(&reply, replyID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Reply not found"})
	}

	// Update the reply with new data
	if err := c.BodyParser(&reply); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := db.DB.Save(&reply).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(reply)
}

func GetRepliesForComment(c *fiber.Ctx) error {
	commentID := uuid.MustParse(c.Params("commentID"))
	var reply []models.Reply
	if err := db.DB.Where("comment_id = ?", commentID).Find(&reply).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Comment not found"})
	}

	return c.JSON(reply)
}

func DeleteReply(c *fiber.Ctx) error {
	// Get the user ID from the context
	userID := c.Locals("id").(string)
	userUUID, err := StringToUUID(userID)
	if err != nil {
		return err
	}

	// Get the reply ID from the request parameters
	replyID := c.Params("replyId")
	replyUUID, err := StringToUUID(replyID)
	if err != nil {
		return err
	}

	var reply models.Reply
	if err := db.DB.First(&reply, replyUUID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Reply not found"})
	}

	// Check if the reply exists
	var existingReply models.Reply
	if err := db.DB.Where("reply_id = ?", replyUUID).Find(&existingReply).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Reply not found",
		})
	}

	// Check if the user is the owner of the reply
	if existingReply.UserID != userUUID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized. You don't have permission to delete this reply",
		})
	}

	// Delete the reply
	if err := db.DB.Delete(&existingReply).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete reply",
		})
	}

	// Decrement the replyCount in the Comment model
	if err := db.DB.Model(&models.Comment{}).Where("comment_id = ?", reply.CommentID).UpdateColumn("reply_count", gorm.Expr("reply_count - 1")).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"input": "Failed to update reply count",
		})
	}
	return c.JSON(fiber.Map{
		"message": "Reply deleted successfully",
	})
}

func GetHashtagsByPostID(c *fiber.Ctx) error {
	// Get the post ID from the request parameters
	postID := c.Params("postID")

	// Check if the post ID is a valid UUID
	parsedPostID, err := uuid.Parse(postID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid post ID",
		})
	}

	// Find the post with the given ID
	var post models.Post
	if err := db.DB.Preload("Hashtags").Where("post_id = ?", parsedPostID).First(&post).Error; err != nil {
		// Handle the error, check if the post doesn't exist
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Post not found",
			})
		}
		// Handle other errors
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error retrieving post",
		})
	}

	// Extract hashtags from the post
	var hashtags []string
	for _, hashtag := range post.Hashtags {
		hashtags = append(hashtags, hashtag.Name)
	}

	// Return the hashtags in the response
	return c.JSON(fiber.Map{
		"postID":   postID,
		"hashtags": hashtags,
	})
}

func GetUserPostVisibility(c *fiber.Ctx) error {
	// Get user ID and post ID from the request parameters
	userID := c.Params("user_id")
	postID := c.Params("post_id")

	// Parse user ID and post ID into UUID format
	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	postIDUUID, err := uuid.Parse(postID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid post ID",
		})
	}

	// Query the database for user post visibility
	var userPostVisibility models.UserPostVisibility
	if err := db.DB.Where("post_id = ? AND post_visibility_user_id = ?", postIDUUID, userIDUUID).First(&userPostVisibility).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User post visibility not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":     "Database error",
			"error_msg": err.Error(),
		})
	}

	// Return user post visibility in the response
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"user_post_visibility": userPostVisibility,
	})
}

// Handler function for reposting a post
func RepostPost(c *fiber.Ctx) error {
	// Get logged in user ID from request context or JWT token
	userIDString := c.Locals("id").(string)

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}
	// Get post ID from request parameters
	postID := c.Params("post_id")

	// Parse post ID into UUID format
	postUUID, err := uuid.Parse(postID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid post ID",
		})
	}

	// Check if the post exists
	var post models.Post
	if err := db.DB.Where("post_id = ?", postUUID).First(&post).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Post not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":     "Database error",
			"error_msg": err.Error(),
		})
	}

	// Check if the post has already been reposted by the user
	var existingRepost models.Repost
	if err := db.DB.Where("post_id = ? AND user_id = ?", postUUID, userID).First(&existingRepost).Error; err == nil {
		// The user has already reposted this post
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "You have already reposted this post",
		})
	}

	// Create a new repost
	newRepost := models.Repost{
		RepostID:  uuid.New(),
		PostID:    postUUID,
		UserID:    userID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save the repost to the database
	if err := db.DB.Create(&newRepost).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":     "Database error",
			"error_msg": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Post reposted successfully",
		"repost":  newRepost,
	})
}

type RepostResponse struct {
	RepostID      uuid.UUID `json:"repost_id"`
	PostID        uuid.UUID `json:"post_id"`
	UserID        uuid.UUID `json:"user_id"`
	UserFirstname string    `json:"user_firstname"`
	UserLastname  string    `json:"user_lastname"`
	UserUrl       string    `json:"user_url"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GetRepostsForPost retrieves reposts for a given post ID and includes user details in the response
func GetRepostsForPost(c *fiber.Ctx) error {
	// Get post ID from request parameters
	postID := c.Params("post_id")

	// Parse post ID into UUID format
	postIDUUID, err := uuid.Parse(postID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid post ID",
		})
	}

	// Query the database to fetch reposts for the given post ID
	var reposts []models.Repost
	if err := db.DB.Where("post_id = ?", postIDUUID).Find(&reposts).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Reposts not found for the given post",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":     "Database error",
			"error_msg": err.Error(),
		})
	}

	// Define a slice to hold the repost responses
	var repostResponses []RepostResponse
	// Iterate over each repost and populate the repost response
	for _, repost := range reposts {
		// Fetch user data for the reposting user
		userData := new(models.User)
		if result := db.DB.Where("uuid = ?", repost.UserID).First(&userData); result.Error != nil {
			continue // Skip if user data not found
		}

		// Create a new RepostResponse object and populate its fields
		newRepostResponse := RepostResponse{
			RepostID:      repost.RepostID,
			PostID:        repost.PostID,
			UserID:        repost.UserID,
			UserFirstname: userData.Firstname,
			UserLastname:  userData.Lastname,
			UserUrl:       userData.Url,
			CreatedAt:     repost.CreatedAt,
			UpdatedAt:     repost.UpdatedAt,
		}

		// Append the new RepostResponse object to the slice
		repostResponses = append(repostResponses, newRepostResponse)
	}

	// Return the repost responses in the JSON format
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"reposts": repostResponses,
	})
}

// DeleteRepost deletes an existing repost
func DeleteRepost(c *fiber.Ctx) error {
	// Parse request parameters to get the repost ID
	repostID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid repost ID",
		})
	}

	// Check if the repost exists
	existingRepost := &models.Repost{}
	if err := db.DB.Where("repost_id = ?", repostID).First(existingRepost).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Repost not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Delete the repost from the database
	if err := db.DB.Delete(existingRepost).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Return response indicating success
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Repost deleted successfully",
	})
}

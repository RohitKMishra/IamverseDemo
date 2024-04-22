package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Emoji struct {
	EmojiID uuid.UUID `gorm:"primaryKey" json:"emoji_id"`
	Name    string    `json:"name"`
	// Add any other fields related to the emoji if needed
}

type EmojiReaction struct {
	EmojiReactionID uuid.UUID `gorm:"primaryKey unique" json:"emoji_reaction_id"`
	PostID          uuid.UUID `json:"post_id"`
	UserID          uuid.UUID `json:"user_id"`
	EmojiID         uuid.UUID `json:"emoji_id"`
	CreatedAt       time.Time `json:"created_at"`
	Post            Post      `gorm:"foreignKey:PostID" json:"post"`
	Emoji           Emoji     `gorm:"foreignKey:EmojiID" json:"emoji"`
}

type UserReaction struct {
	// UserReactionID uuid.UUID `gorm:"primaryKey" json:"user_reaction_id"`
	UserID       uuid.UUID `gorm:"primaryKey" json:"user_id"`
	PostID       uuid.UUID `gorm:"primaryKey" json:"post_id"`
	ReactionName string    `json:"reaction_name"`
}

type UserPostVisibility struct {
	UserPostVisibilityID uuid.UUID `gorm:"primaryKey" json:"user_post_visibility_id"`
	PostID               uuid.UUID `gorm:"type:uuid;not null" json:"post_id"`
	PostVisibilityUserID uuid.UUID `gorm:"type:uuid;not null" json:"post_visibility_user_id"`
	Visible              bool      `gorm:"default:true" json:"visible"`
}

func (UserPostVisibility) TableName() string {
	return "user_post_visibility"
}

// Repost represents a repost of a post in the system.
type Repost struct {
	RepostID  uuid.UUID `gorm:"primaryKey" json:"repost_id"`
	PostID    uuid.UUID `json:"post_id"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Post struct {
	PostID               uuid.UUID            `gorm:"primaryKey" json:"post_id"`
	PostUserID           uuid.UUID            `json:"post_user_id"`
	PostTitle            string               `json:"post_title"`
	PostContent          string               `json:"post_content"`
	PostImage            string               `json:"post_image"`
	PostVideo            string               `json:"post_video"`
	PostURL              string               `json:"post_url"`
	UserPostVisibilities []UserPostVisibility `gorm:"foreignKey:PostID"`
	Dislikes             int                  `json:"dislikes"`
	Likers               pq.StringArray       `gorm:"type:text[]" json:"likers"`
	Dislikers            pq.StringArray       `gorm:"type:uuid[]" json:"dislikers"`
	Comments             []Comment            `gorm:"polymorphic:Parent;polymorphicValue:post" json:"comments"`
	Likes                []Like               `gorm:"polymorphic:Likeable;polymorphicValue:post" json:"likes"`
	LikesCount           int                  `json:"likes_count"`
	CommentCount         int                  `json:"comment_count"`
	Hashtags             []Hashtag            `gorm:"many2many:post_hashtags;" json:"hashtags"`
	Mentions             pq.StringArray       `gorm:"type:text[]" json:"mentions"`
	TaggedUserIDs        pq.StringArray       `gorm:"type:uuid[]" json:"tagged_user_ids"`
	EmojiReactions       []EmojiReaction      `gorm:"foreignKey:PostID" json:"emoji_reactions"`
	UserReaction         UserReaction         `gorm:"foreignKey:PostID" json:"user_reaction"`
	CelebrateCount       int                  `json:"celebrate_count"`
	SupportCount         int                  `json:"support_count"`
	LoveCount            int                  `json:"love_count"`
	InsightfulCount      int                  `json:"insightful_count"`
	FunnyCount           int                  `json:"funny_count"`
	LikeEmojiCount       int                  `json:"like_emoji_count"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
	Reposts              []Repost             `gorm:"foreignKey:PostID" json:"reposts"`
}

// Comment represents a comment in the system.
type Comment struct {
	CommentID  uuid.UUID      `gorm:"primaryKey" json:"comment_id"`
	PostID     uuid.UUID      `json:"post_id" gorm:"index"`
	ParentID   uuid.UUID      `json:"parent_id" gorm:"index"`
	ParentType string         `json:"parent_type" gorm:"index"` // Added field for polymorphic relationship
	UserID     uuid.UUID      `json:"user_id"`
	Content    string         `gorm:"not null" json:"content"`
	Likes      []Like         `gorm:"polymorphic:Likeable;polymorphicValue:comment" json:"likes"`
	Likers     pq.StringArray `gorm:"type:text[]" json:"likers"`
	LikeCount  int            `json:"like_count"`
	ReplyCount int            `json:"reply_count"`
	Replies    []Reply        `gorm:"polymorphic:Parent;polymorphicValue:comment" json:"replies"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// Like represents a like in the system.
type Like struct {
	LikeID       uuid.UUID `gorm:"primaryKey" json:"like_id"`
	UserID       uuid.UUID `json:"user_id"`
	LikeableID   uuid.UUID `json:"likeable_id"`
	LikeableType string    `json:"likeable_type"`
	LikeStatus   bool      `json:"like_status"`
	Emoji        Emoji     `gorm:"embedded" json:"emoji"`
	CreatedAt    time.Time `json:"created_at"`
}

// Reply represents a reply in the system.
type Reply struct {
	ReplyID    uuid.UUID `gorm:"primaryKey" json:"reply_id"`
	CommentID  uuid.UUID `json:"comment_id" gorm:"index"`
	ParentID   uuid.UUID `json:"parent_id" gorm:"index"`
	ParentType string    `json:"parent_type" gorm:"index"` // Added field for polymorphic relationship
	UserID     uuid.UUID `json:"user_id"`
	Content    string    `gorm:"not null" json:"content"`
	Likes      []Like    `gorm:"polymorphic:Likeable;polymorphicValue:reply" json:"likes"`
	LikeCount  int       `json:"like_count"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

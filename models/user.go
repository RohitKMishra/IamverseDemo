package models

import (
	// "time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/lib/pq"
	// "gorm.io/gorm"
)

type User struct {
	Base
	UserID uuid.UUID `gorm:"foreignKey:ID;references:users"`
	// Foreign key referencing the `ID` field in the `User` struct

	Firstname       string         `json:"firstname"`
	Lastname        string         `json:"lastname"`
	Url             string         `json:"url" gorm:"unique"`
	Emails          pq.StringArray `json:"emails" gorm:"type:text[]"`
	Password        string         `json:"password"`
	Countrycode     string         `json:"countrycode"`
	Phone           pq.StringArray `json:"phone" gorm:"type:text[]"`
	Dob             string         `json:"dob"`
	Role            string         `json:"role"`
	IsEmailVerified string         `json:"isEmailVerified"`
	Picture         string         `json:"picture"`
	Address         string         `json:"address"`
	Banner          string         `json:"banner"`
	Country         string         `json:"country"`
	City            string         `json:"city"`
	State           string         `json:"state"`
	PortfolioUrl    string         `json:"portfolio_url"`
	// UserProfile     UserProfile    `gorm:"foreignKey:UserID;references:UUID" json:"user_profile"`
	RecipientID uuid.UUID `json:"recipient_id" gorm:"type:uuid;"`
	// Groups          []Group        `gorm:"many2many:user_groups;foreignKey:UserID;joinForeignKey:user_uuid;joinReferences:UUID"`

	Followers []User `gorm:"many2many:follower_following;foreignKey:UUID;joinForeignKey:follower_id;joinReferences:FollowingID"`
	Following []User `gorm:"many2many:follower_following;foreignKey:UUID;joinForeignKey:following_id;joinReferences:FollowerID"`
	// AppliedJobs  []Job           `gorm:"many2many:jobs;"`
	// Causes       []Cause         `gorm:"foreignKey:CauseUserID;references:UUID" json:"causes"`
	Skills []string `gorm:"type:text[]" json:"skills"`
	// WSConnection *websocket.Conn `gorm:"-"`
	Verified bool `json:"verified" gorm:"default:false"`
}

// User error represent the error format for user routes
type UserErrors struct {
	Err         bool   `json:"error"`
	Countrycode string `json:"countrycode"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Firstname   string `json:"firstname"`
	Lastname    string `json:"lastname"`
}

// Claims represent the structure of the JWT token
type Claims struct {
	jwt.StandardClaims
	ID   uint   `gorm:"primaryKey"`
	UUID string `json:"uuid"`
}

// Represent the struct of the about schema
type About struct {
	AboutID          uuid.UUID `json:"about_id" gorm:"primaryKey;unique;not null"`
	AboutUserID      uuid.UUID `json:"about_user_id"`
	AboutDescription string    `json:"about_description"`
}

// Represent the struct of Address schema

type Address struct {
	AddressID      uuid.UUID `json:"address_id" gorm:"primaryKey;unique;not null"`
	AddressUserID  uuid.UUID `json:"address_user_id"`
	AddressLine1   string    `json:"address_line_1"`
	AddressLine2   string    `json:"address_line_2"`
	AddressCity    string    `json:"address_city"`
	AddressState   string    `json:"address_state"`
	AddressCountry string    `json:"address_country"`
	AddressPincode string    `json:"address_pincode"`
}

// Represents the struct of Certification schema

type Certifications struct {
	CertificationsID                  uuid.UUID `json:"certifications_id" gorm:"primaryKey;unique;not null"`
	CertificationsUserID              uuid.UUID `json:"certifications_user_id"`
	CertificationsName                string    `json:"certifications_name"`
	CertificationsIssuingOrganization string    `json:"certifications_issuing_organization"`
	CertificationsIssueDate           string    `json:"certifications_issue_date"`
	CertificationsStartMonth          string    `json:"certifications_start_month"`
	CertificationsStartYear           string    `json:"certifications_start_year"`
	CertificationsEndMonth            string    `json:"certifications_end_month"`
	CertificationsEndYear             string    `json:"certifications_end_year"`
	InstituteLogo                     string    `json:"institute_logo"`
	CertificationsInstituteURL        string    `json:"certifications_institute_url"`
}

// Represents the struct of Education schema

type Education struct {
	EducationID                uuid.UUID      `json:"education_id" gorm:"primaryKey;unique;not null"`
	EducationUserID            uuid.UUID      `json:"education_user_id" `
	BasicInfoID                uuid.UUID      `json:"basic_info_id" gorm:"default:null"`
	EducationUniversityBoard   string         `json:"eductaion_university_board"`
	EducationUniversityCountry string         `json:"education_university_country"`
	EducationBranch            string         `json:"education_branch"`
	EducationDegree            string         `json:"education_degree"`
	EducationStartMonth        string         `json:"education_start_month"`
	EducationStartYear         string         `json:"education_start_year"`
	EducationEndMonth          string         `json:"education_end_month"`
	EducationEndYear           string         `json:"education_end_year"`
	EducationDispIntro         bool           `json:"education_disp_intro" gorm:"default:true"`
	EducationActivities        string         `json:"education_activities"`
	InstituteLogo              string         `json:"institute_logo"`
	EducationImage             pq.StringArray `gorm:"type:text[]" json:"education_image"`
}

type Experience struct {
	ExperienceID               uuid.UUID      `json:"experience_id" gorm:"primaryKey;unique;not null"`
	ExperienceUserID           uuid.UUID      `json:"experience_user_id"`
	BasicInfoID                uuid.UUID      `json:"basic_info_id" gorm:"default:null"`
	ExperienceCompanyName      string         `json:"experience_company_name"`
	ExperienceDesignation      string         `json:"experience_designation"`
	ExperienceStartMonth       string         `json:"experience_start_month"`
	ExperienceStartYear        string         `json:"experience_start_year"`
	ExperienceEndMonth         string         `json:"experience_end_month"`
	ExperienceEndYear          string         `json:"experience_end_year"`
	ExperienceMostLatestJob    string         `json:"experience_most_latest_job"`
	ExperienceResponsibilities string         `json:"experience_responsibilities"`
	ExperienceType             string         `json:"experience_type" gorm:"default:''"`
	ExperienceLocation         string         `json:"experience_location" gorm:"default:''"`
	ExperienceLocationType     string         `json:"experience_location_type" gorm:"default:''"`
	ExperienceDescription      string         `json:"experience_description"`
	CompanyLogo                string         `json:"company_logo"`
	ExperienceImage            pq.StringArray `gorm:"type:text[]" json:"experience_image"`
}

type GetUserExpDesComName struct {
	ExperienceId          string `json:"experience_id" gorm:"primaryKey;unique;not null"`
	ExperienceUserId      string `json:"experience_user_id"`
	ExperienceCompanyName string `json:"experience_company_name"`
	ExperienceDesignation string `json:"experience_designation"`
}

type BasicInfo struct {
	BasicInfoID    uuid.UUID    `json:"basic_info_id" gorm:"primaryKey;unique;not null"`
	BasicUserID    uuid.UUID    `json:"basic_user_id"`
	Firstname      string       `json:"firstname"`
	Lastname       string       `json:"lastname"`
	Industry       string       `json:"industry"`
	AdditionalName string       `json:"additional_name"`
	Pronouns       string       `json:"pronouns"`
	Headline       string       `json:"headline"`
	City           string       `json:"city"`
	Country        string       `json:"country"`
	Education      []Education  `json:"education" gorm:"foreignKey:BasicInfoID"`
	Position       []Experience `json:"position" gorm:"foreignKey:BasicInfoID"`
}

type DemographicInfo struct {
	DemographicInfoUserId uuid.UUID `json:"demographic_info_user_id" gorm:"primaryKey;unique;not null"`
	Gender                string    `json:"gender"`
	Disability            string    `json:"disability"`
}

type Course struct {
	CourseID           uuid.UUID `json:"course_id" gorm:"primaryKey;unique;not null"`
	CourseUserID       uuid.UUID `json:"course_user_id"`
	CourseName         string    `json:"course_name"`
	CourseNumber       string    `json:"course_number"`
	AssociatedWith     string    `json:"associated_with"`
	CourseStartMonth   string    `json:"course_start_month"`
	CourseStartYear    string    `json:"course_start_year"`
	CourseEndMonth     string    `json:"course_end_month"`
	CourseEndYear      string    `json:"course_end_year"`
	InstituteLogo      string    `json:"institute_logo"`
	CourseInstituteURL string    `json:"course_institute_url"`
}

type Project struct {
	ProjectID          uuid.UUID `json:"project_id" gorm:"primaryKey;unique;not null"`
	ProjectUserId      uuid.UUID `json:"project_user_id"`
	ProjectName        string    `json:"project_name"`
	ProjectDescription string    `json:"project_description"`
	ProjectURL         string    `json:"project_url"`
	StartMonth         string    `json:"start_month"`
	EndMonth           string    `json:"end_month"`
	StartYear          string    `json:"start_year"`
	EndYear            string    `json:"end_year"`
	Skills             []Skill   `json:"skills" gorm:"many2many:project_skills;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:ProjectID;joinForeignKey:SkillID;References:SkillID"`
	Media              []Media   `json:"media" gorm:"many2many:project_media;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:ProjectID;joinForeignKey:MediaID;References:MediaID"`
	Contributors       string    `json:"contributors"`
	AdditionalDetails  string    `json:"additional_details"`
}

type Skill struct {
	SkillID     uuid.UUID `json:"skill_id" gorm:"primaryKey;unique;not null"`
	Name        string    `json:"name"`
	Proficiency string    `json:"proficiency"`
	UserID      uuid.UUID `json:"user_id"`
}

type Media struct {
	MediaID     uuid.UUID `json:"media_id" gorm:"primaryKey;unique;not null"`
	Link        string    `json:"link"`
	UploadMedia string    `json:"upload_url"`
}

type Language struct {
	LanguageID          uuid.UUID `json:"language_id" gorm:"primaryKey;unique;not null"`
	LanguageName        string    `json:"language_name"`
	LanguageProficiency string    `json:"language_proficiency"`
	UserID              uuid.UUID `json:"user_id"`
}

type Follower struct {
	FollowerEntryID uuid.UUID `json:"follower_entry_id" gorm:"primaryKey"`
	FollowerID      uuid.UUID `json:"follower_id" gorm:"primaryKey"`
	UUID            uuid.UUID `json:"user_id"`
}

type Following struct {
	FollowingEntryID uuid.UUID `json:"following_entry_id" gorm:"primaryKey"`
	UUID             uuid.UUID `json:"user_id"`
	FollowingID      uuid.UUID `json:"following_id" gorm:"primaryKey"`
}

// type CareerBreak struct {
// 	CareerBreakID     uuid.UUID `json:"career_break_id" gorm:"type:uuid;primaryKey;not null"`
// 	CareerBreakUserID uuid.UUID `json:"career_break_user_id"`
// 	StartMonth        string    `json:"start_month"`
// 	EndMonth          string    `json:"end_month"`
// 	StartYear         string    `json:"start_year"`
// 	EndYear           string    `json:"end_year"`
// 	Reason            string    `json:"reason"`
// 	Description       string    `json:"description"`
// }

// type VolunteerExperience struct {
// 	VolunteerExperienceID uuid.UUID `json:"volunteer_experience_id" gorm:"type:uuid;primaryKey;not null"`
// 	VolunteerUserID       uuid.UUID `json:"volunteer_user_id"`
// 	Role                  string    `json:"role"`
// 	Organization          string    `json:"organization"`
// 	Cause                 string    `json:"cause"`
// 	Location              string    `json:"location"`
// 	StartMonth            string    `json:"start_month"`
// 	EndMonth              string    `json:"end_month"`
// 	StartYear             string    `json:"start_year"`
// 	EndYear               string    `json:"end_year"`
// 	Description           string    `json:"description"`
// 	CompanyLogo           string    `json:"company_logo"`
// 	Url                   string    `json:"url"`
// }

// type Publication struct {
// 	PublicationsID    uuid.UUID `json:"publications_id" gorm:"primaryKey;type:uuid"`
// 	PublicationUserID uuid.UUID `json:"publication_user_id" gorm:"type:uuid"`
// 	Title             string    `json:"title"`
// 	PublishedDate     string    `json:"published_date"`
// 	Publisher         string    `json:"publisher"`
// 	PublicationURL    string    `json:"publication_url"`
// 	Description       string    `json:"description"`
// }

// type Patent struct {
// 	PatentID     uuid.UUID `json:"patent_id" gorm:"type:uuid;primaryKey"`
// 	PatentUserID uuid.UUID `json:"patent_user_id"`
// 	Title        string    `json:"title"`
// 	PatentOffice string    `json:"patent_office"`
// 	PatentNumber string    `json:"patent_number"`
// 	IssueDate    string    `json:"issue_date"`
// 	Description  string    `json:"description"`
// 	Status       string    `json:"status"`
// 	Url          string    `json:"url"`
// }

// type TestScore struct {
// 	TestScoreID     uuid.UUID `json:"test_score_id" gorm:"type:uuid;primaryKey"`
// 	TestScoreUserID uuid.UUID `json:"test_score_user_id"`
// 	TestName        string    `json:"test_name"`
// 	Score           float64   `json:"score"`
// 	Date            string    `json:"date"`
// 	Description     string    `json:"description"`
// 	Associated      string    `json:"associated"`
// }

// type Organization struct {
// 	OrganizationID     uuid.UUID `json:"organization_id" gorm:"type:uuid;primaryKey;not null"`
// 	OrganizationUserID uuid.UUID `json:"organization_user_id" gorm:"type:uuid;not null"`
// 	Name               string    `json:"name"`
// 	Position           string    `json:"position"`
// 	StartMonth         string    `json:"start_month"`
// 	EndMonth           string    `json:"end_month"`
// 	StartYear          string    `json:"start_year"`
// 	EndYear            string    `json:"end_year"`
// 	Description        string    `json:"description"`
// }

// type Cause struct {
// 	CauseUserID uuid.UUID      `gorm:"type:uuid;foreignKey:UserReferID;references:UUID" json:"cause_user_id"`
// 	CauseID     uuid.UUID      `gorm:"type:uuid;not null" json:"cause_id"`
// 	Name        pq.StringArray `gorm:"type:text[];not null" json:"name"`
// 	User        User           `gorm:"foreignKey:CauseUserID;references:UUID"`
// }
// type CauseResponse struct {
// 	CauseID     uuid.UUID      `json:"cause_id"`
// 	CauseUserID uuid.UUID      `json:"cause_user_id"`
// 	Name        pq.StringArray `gorm:"type:text[]" json:"name"`
// }

// type Recommendation struct {
// 	RecommendationID    uuid.UUID `json:"recommendation_id" gorm:"type:uuid;primaryKey;not null"`
// 	UserID              uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
// 	RecommenderName     string    `json:"recommender_name"`
// 	RecommenderPosition string    `json:"recommender_position"`
// 	Relationship        string    `json:"relationship"`
// 	RecommendationText  string    `json:"recommendation_text"`
// 	CreatedAt           time.Time `json:"created_at"`
// }

// type Group struct {
// 	Base
// 	GroupID     uuid.UUID `json:"group_id" gorm:"type:uuid;primaryKey;not null; unique"`
// 	Name        string    `json:"name"`
// 	Description string    `json:"description"`
// 	Users       []User    `gorm:"many2many:user_groups;foreignKey:GroupID;joinForeignKey:group_uuid;joinReferences:UUID"`
// }

// type GroupMember struct {
// 	GroupMemberID uuid.UUID `json:"group_member_id" gorm:"type:uuid;primaryKey;not null"`
// 	GroupID       uuid.UUID `json:"group_id" gorm:"type:uuid;not null"`
// 	UserID        uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
// }

// type GroupPost struct {
// 	PostID        uuid.UUID          `json:"post_id" gorm:"type:uuid;primaryKey;not null"`
// 	GroupID       uuid.UUID          `json:"group_id" gorm:"type:uuid;not null"`
// 	UserID        uuid.UUID          `json:"user_id" gorm:"type:uuid;not null"`
// 	Content       string             `json:"content"`
// 	Title         string             `json:"title"`
// 	Image         string             `json:"image"`
// 	Video         string             `json:"video"`
// 	URL           string             `json:"url"`
// 	Likes         []GroupPostLike    `gorm:"polymorphic:Likeable;polymorphicValue:grouppost" json:"likes"`
// 	Likers        pq.StringArray     `gorm:"type:text[]" json:"likers"`
// 	Dislikes      int                `json:"dislikes"`
// 	Dislikers     pq.StringArray     `gorm:"type:uuid[]" json:"dislikers"`
// 	Comments      []GroupPostComment `gorm:"polymorphic:Parent;polymorphicValue:grouppost" json:"comments"`
// 	LikesCount    int                `json:"likes_count"`
// 	CommentCount  int                `json:"comment_count"`
// 	Hashtags      []Hashtag          `gorm:"many2many:grouppost_hashtags;" json:"hashtags"`
// 	Mentions      pq.StringArray     `gorm:"type:text[]" json:"mentions"`
// 	TaggedUserIDs pq.StringArray     `gorm:"type:uuid[]" json:"tagged_user_ids"`
// 	CreatedAt     time.Time          `json:"posted_at"`
// 	UpdatedAt     time.Time          `json:"updated_at"`
// }

// // GroupPostLike represents a like on a group post.
// type GroupPostLike struct {
// 	GroupPostLikeID uuid.UUID `gorm:"type:uuid;primaryKey" json:"group_post_like_id"`
// 	GroupPostID     uuid.UUID `json:"group_post_id" gorm:"type:uuid;not null"`
// 	UserID          uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
// 	LikeableID      uuid.UUID `json:"likeable_id"`
// 	LikeableType    string    `json:"likeable_type"`
// 	LikeStatus      bool      `json:"like_status"`
// 	LikedAt         time.Time `json:"liked_at"`
// }

// type GroupPostComment struct {
// 	GroupPostCommentID uuid.UUID `json:"group_post_comment_id" gorm:"type:uuid;primaryKey;not null"`
// 	PostID             uuid.UUID `json:"post_id" gorm:"index"`
// 	ParentID           uuid.UUID `json:"parent_id" gorm:"index"`
// 	ParentType         string    `json:"parent_type" gorm:"index"` // Added field for polymorphic relationship
// 	UserID             uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
// 	Content            string    `json:"content"`

// 	LikesCount int                     `json:"group_post_comment_likes_count"`
// 	ReplyCount int                     `json:"reply_count"`
// 	Likes      []GroupPostCommentLike  `gorm:"polymorphic:Likeable;polymorphicValue:comment" json:"group_comment_likes"`
// 	Replies    []GroupPostCommentReply `gorm:"polymorphic:Parent;polymorphicValue:comment" json:"replies"`
// 	CreatedAt  time.Time               `json:"created_at"`
// 	UpdatedAt  time.Time               `json:"updated_at"`
// }
// type GroupPostCommentReply struct {
// 	GroupPostCommentReplyID uuid.UUID       `json:"group_post_comment_reply_id" gorm:"type:uuid;primaryKey;not null"`
// 	CommentID               uuid.UUID       `json:"comment_id" gorm:"type:uuid;not null"`
// 	ParentID                uuid.UUID       `json:"parent_id" gorm:"index"`
// 	ParentType              string          `json:"parent_type" gorm:"index"`
// 	UserID                  uuid.UUID       `json:"user_id" gorm:"type:uuid;not null"`
// 	Likes                   []GroupPostLike `gorm:"polymorphic:Likeable;polymorphicValue:reply" json:"likes"`
// 	LikeCount               int             `json:"like_count"`
// 	Content                 string          `json:"content"`
// 	CreatedAt               time.Time       `json:"created_at"`
// }

// type GroupPostCommentLike struct {
// 	GroupPostCommentLikeID uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;not null"`
// 	LikeableID             uuid.UUID `json:"likeable_id"`
// 	LikeableType           string    `json:"likeable_type"`
// 	UserID                 uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
// 	CreatedAt              time.Time `json:"created_at"`
// }

// func (u *User) GetNotifications(db *gorm.DB) ([]notifications.Notification, error) {
// 	var notifications []notifications.Notification
// 	if err := db.Where("recipient_id = ?", u.UUID).Find(&notifications).Error; err != nil {
// 		return nil, err
// 	}

// 	return notifications, nil
// }

// // GetUserByID retrieves a user by their ID
// func GetUserByID(db *gorm.DB, userID string) *User {
// 	var user User
// 	db.Where("user_id = ?", userID).First(&user)
// 	return &user
// }

// // Define the user profile model
// type UserProfile struct {
// 	UserProfileID uuid.UUID      `gorm:"type:uuid;primaryKey" json:"user_profile_id"`
// 	UserID        uuid.UUID      `gorm:"type:uuid;unique;not null" json:"user_id"` // ID of the profile user
// 	Username      string         `json:"username"`                                 // Other profile fields
// 	Visitors      pq.StringArray `gorm:"type:text[]" json:"visitors"`              // Store visitor user IDs
// }

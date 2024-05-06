package userroutes

import (
	// db is an alias for package codeapto-backend/database

	"github.com/RohitKMishra/IamverseDemo/controllers"
	"github.com/RohitKMishra/IamverseDemo/util"
	"github.com/gofiber/fiber/v2"
)

// SetupUserRoutes func sets up all the user routes
func SetupUserRoutes(USER fiber.Router) {
	USER.Post("/signup", controllers.CreateUser)              // Sign Up a user
	USER.Post("/signin", controllers.LoginUser)               // Sign In a user
	USER.Get("/get-access-token", controllers.GetAccessToken) // returns a new access_token
	USER.Post("/social_login", controllers.SocialLogin)
	USER.Post("/logout", controllers.LogoutUser)

	// Middleware
	USER.Use(util.SecureAuth()) // middleware to secure all routes for this group

	// Users
	// USER.Put("/update_user_details", controllers.UpdateUserData)
	USER.Get("/fetch_user_details", controllers.UserViewFnLnPhExpAll)
	// USER.Put("/user_location", controllers.UpdateUserLocation)
	// USER.Get("/all_users", controllers.GetAllUsers)
	USER.Get("/view_user_by_id/:id", controllers.GetUserDetailsByID)
	// USER.Get("/fetch_user_url/:url", controllers.GetUserByUrl)
	// USER.Post("/update_user_url/:url", controllers.UpdateUserUrl)
	// USER.Get("/search", controllers.SearchHandler)

	// Basic Info
	// USER.Post("/basic_info_create", controllers.CreateBasicInfo)
	// USER.Get("/basic_info_view/:id", controllers.GetBasicInfo)
	// USER.Put("/basic_info_update/:id", controllers.UpdateBasicInfo)
	// USER.Delete("/basic_info_delete/:id", controllers.DeleteBasicInfo)

	// // About
	// USER.Post("/about_creation", controllers.CreateAbout)
	// USER.Get("/about_view", controllers.GetAboutData)
	// USER.Get("/about_view_by_about_id/:id", controllers.GetAboutByID)
	// USER.Get("/about_view_by_user_id/:id", controllers.GetAboutByUserID)
	// USER.Put("/about_update", controllers.UpdateAboutData)
	// USER.Put("/about_update_by_about_id/:id", controllers.UpdateAboutByAboutID)
	// USER.Delete("/about_delete_by_about_id/:id", controllers.DeleteAboutByAboutID)
	// USER.Delete("/about_delete_by_user_id/:id", controllers.DeleteAboutByUserID)

	// // Address
	// USER.Post("/address_creation", controllers.CreateAddress)
	// USER.Get("/address_view", controllers.GetAddress)
	// USER.Get("/address_view_by_add_id/:id", controllers.GetAddressByAddressID)
	// USER.Get("/address_view_by_user_id/:id", controllers.GetAddressByUserID)
	// USER.Put("/address_update", controllers.UpdateAddress)

	// // Certificates
	// USER.Post("/certification_creation", controllers.CreateCertification)
	// USER.Get("/certification_view", controllers.GetCertification)
	// USER.Get("/certification_view_by_cert_id/:id", controllers.GetCertificationByCertID)
	// USER.Get("/certification_view_by_user_id/:id", controllers.GetCertificationByUserID)
	// USER.Put("/certification_update", controllers.UpdateCertification)
	// USER.Put("/certification_update_by_cert_id/:id", controllers.UpdateCertByCertID)
	// USER.Delete("/certification_delete_by_cert_id/:id", controllers.DeleteCertByEduID)

	// // Education
	// USER.Post("/education_creation", controllers.CreateEducation)
	// USER.Get("/education_view", controllers.GetEducation)
	// USER.Get("/education_view_by_edu_id/:id", controllers.GetEducationByEducationID)
	// USER.Get("/education_view_by_user_id/:id", controllers.GetEducationByUserID)
	// USER.Put("/education_update_by_user_id", controllers.GetEducationByUserID)
	// USER.Put("/education_update_by_edu_id/:id",
	// 	controllers.UpdateEduByEduID)
	// USER.Delete("/education_delete", controllers.DeleteEdu)
	// USER.Delete("/education_delete_by_edu_id/:id", controllers.DeleteEduByEduID)
	// USER.Get("/get_user_edu_uni_name", controllers.GetUserEduUniName)

	// // Experience
	// USER.Post("/experience_creation", controllers.CreateExperience)
	// USER.Get("/experience_view", controllers.GetExperience)
	// USER.Get("/experience_view_by_exp_id/:id", controllers.GetExperienceByExpID)
	// USER.Put("/experience_update",
	// 	controllers.UpdateExperienceByUserID)
	// USER.Put("/experience_update_by_exp_id/:id",
	// 	controllers.UpdateExperienceByExpID)
	// USER.Get("/experience_view_by_user_id/:id", controllers.GetExperienceByUserID)
	// USER.Delete("/experience_delete", controllers.DeleteExperience)
	// USER.Delete("/experience_delete_by_exp_id/:id", controllers.DeleteExperienceByExpID)
	// USER.Get("/get_user_exp_des_com_name", controllers.GetUserExpDesComName)

	//POST
	USER.Post("/post_creation", controllers.CreatePost)
	USER.Get("/post_view", controllers.GetPosts) // to get all post of logged in user
	USER.Get("/post_view/:id", controllers.GetPost)
	USER.Get("/post_view_by_url/:url", controllers.GetPostByURL)
	USER.Delete("/post_delete/:id", controllers.DeletePost)
	USER.Get("/all_posts", controllers.GetAllPosts) // to get all posts
	USER.Put("/post_update/:id", controllers.UpdatePost)

	// // Headline
	// USER.Post("/headline_creation", controllers.CreateHeadline)
	// USER.Get("/headline_view_by_user_id/:id", controllers.GetHeadlineByUserID)
	// USER.Get("/headline_view_by_headline_id/:id", controllers.GetHeadlineByHeadlineID)
	// USER.Put("/headline_update_by_headline_id/:id", controllers.UpdateHeadline)
	// USER.Delete("/headline_delete_by_headline_id/:id", controllers.DeleteHeadline)

	// Comment
	USER.Post("/comment_creation", controllers.CreateComment)
	USER.Get("/comment_view/:commentID", controllers.GetCommentByCommentID)
	USER.Get("/comment_view_by_post_id/:postID", controllers.GetCommentByPostID)
	USER.Put("/comment_update/:commentID", controllers.UpdateComment)
	USER.Delete("/comment_delete/:id", controllers.DeleteComment)

	// Reply
	USER.Post("/create_comments/replies", controllers.CreateReply)
	USER.Put("/replies/:id", controllers.UpdateReply)
	USER.Get("/comments/:commentID/replies/", controllers.GetRepliesForComment)
	USER.Delete("/comments/replies_delete/:replyId", controllers.DeleteReply)

	// Like for comment
	USER.Post("/like/post", controllers.LikePost)
	USER.Post("/like/comment", controllers.LikeComment)
	USER.Get("/posts/:postID/like", controllers.GetLikePost)
	USER.Get("/comments/:commentID/like", controllers.GetLikeComment)

	//Emoji
	USER.Post("/create_emoji", controllers.CreateEmojiHandler)
	USER.Get("/posts/:postID/reaction", controllers.GetUserReactionByPostID)
	USER.Get("/getEmojiByEmojiName/:reactionName", controllers.GetEmojiDetailsByReactionName)

	// New route for calling the Stripe payment API
	USER.Post("/make_payment", controllers.MakeStripePayment)

	// Skill

	// USER.Post("/skill_creation", controllers.CreateSkill)
	// USER.Get("/skill_view", controllers.GetSkills)
	// USER.Get("/skill_view_by_user_id/:id", controllers.GetSkillsByUserID)
	// USER.Delete("/skill_delete/:id", controllers.DeleteSkill)
	// USER.Put("/skill_update/:id", controllers.UpdateSkill)

	// // Course
	// USER.Post("/course_creation", controllers.CreateCourse)
	// USER.Get("/course_view", controllers.GetCourse)
	// USER.Get("/course_view_by_user_id/:id", controllers.GetCoursesByUserID)
	// USER.Put("/course_update/:id", controllers.UpdateCourse)
	// USER.Delete("/course_delete/:id", controllers.DeleteCourse)

	// //	DemographicInfo
	// USER.Post("/demographic_creation", controllers.CreateDemographicInfo)
	// USER.Get("/demographic_view", controllers.GetDemographicInfo)
	// USER.Put("/demographic_update/:id", controllers.UpdateDemographicInfo)
	// USER.Delete("/demographic_delete/:id", controllers.DeleteDemographicInfo)

	// // Project
	// USER.Post("/projects_creation", controllers.CreateProject)
	// USER.Get("/projects_view/:id", controllers.GetProject)
	// USER.Get("/projects_view_by_user_id/:id", controllers.GetProjectsByUserID)
	// USER.Get("/view_project_by_url/:url", controllers.GetProjectByURL)
	// USER.Put("/projects_update/:id", controllers.UpdateProject)
	// USER.Delete("/projects_delete/:id", controllers.DeleteProject)

	// // HonorAward
	// USER.Post("/honorawards_creation", controllers.CreateHonorAward)
	// USER.Get("/honorawards_view", controllers.GetHonorAwards)
	// USER.Get("/honorawards_view_by_award_id/:id", controllers.GetHonorAwardByID)
	// USER.Get("/honorawards_view_by_user_id/:id", controllers.GetHonorAwardsByUserID)
	// USER.Put("/honorawards_update/:id", controllers.UpdateHonorAward)
	// USER.Delete("/honorawards_delete/:id", controllers.DeleteHonorAward)

	// // Career Break
	// USER.Post("/career_break_creation", controllers.CreateCareerBreak)
	// USER.Get("/career_break_view", controllers.GetCareerBreak)
	// USER.Get("/career_break_view_by_cb_id/:id", controllers.GetCareerBreakByCBrkID)
	// USER.Put("/career_break_update_by_user_id", controllers.UpdateCareerBreak)
	// USER.Put("/career_break_update_by_cb_id/:id", controllers.UpdateCareerBreakByCBrkID)
	// USER.Delete("/career_break_delete_by_user_id", controllers.DeleteCareerBreakByUserID)
	// USER.Delete("/career_break_delete_by_cb_id/:id", controllers.DeleteCareerBreakByCareerBreakID)

	// // Volunteer Experience
	// USER.Post("/volunteer_experience_creation", controllers.CreateVolunteerExperience)
	// USER.Get("/volunteer_experience_view_by_user_id/:id", controllers.GetVolunteerExperienceByUserID)
	// USER.Get("/volunteer_experience_view_by_vol_exp_id/:id", controllers.GetVolunteerExperienceByVolExpId)
	// USER.Put("/volunteer_experience_update", controllers.UpdateVolunteerExperience)
	// USER.Put("/volunteer_experience_update_by_vol_exp_id/:id", controllers.UpdateVolunteerExperienceByVoluntExpID)
	// USER.Delete("/volunteer_experience_delete_by_user_id", controllers.DeleteVolunteerExperienceByUserID)
	// USER.Delete("/volunteer_experience_delete_by_vol_exp_id/:id", controllers.DeleteVolunteerExperienceByVolunteerExperienceID)

	// // Publications
	// USER.Post("/publication_creation", controllers.CreatePublication)
	// USER.Get("/publication_view_by_user_id/:id", controllers.GetPublicationsByUserID)
	// USER.Get("/publication_view_by_pub_id/:id", controllers.GetPublicationsByPubID)
	// USER.Put("/publication_update", controllers.UpdatePublication)
	// USER.Put("/publication_update_by_pub_id/:id", controllers.UpdatePublicationByPubID)
	// USER.Delete("/publication_delete_by_pub_id/:id", controllers.DeletePublication)

	// // Patents
	// USER.Post("/patent_creation", controllers.CreatePatent)
	// USER.Get("/patent_view_by_user_id/:id", controllers.GetPatents)
	// USER.Get("/patent_view_by_pat_id/:id", controllers.GetPatentByPatentID)
	// USER.Put("/patent_update", controllers.UpdatePatent)
	// USER.Put("/patent_update_by_pat_id/:id", controllers.UpdatePatentByPatentID)
	// USER.Delete("/patent_delete_by_pat_id/:id", controllers.DeletePatentByPatentID)

	// // Test Scores
	// USER.Post("/test_score_creation", controllers.CreateTestScore)
	// USER.Get("/test_scores_view_by_user_id/:id", controllers.GetTestScores)
	// USER.Get("/test_scores_view_by_ts_id/:id", controllers.GetTestScoreByID)
	// USER.Put("/test_score_update_by_ts_id/:id", controllers.UpdateTestScoreByTSID)
	// USER.Delete("/test_score_delete_by_ts_id/:id", controllers.DeleteTestScore)

	// // Organization
	// USER.Post("/organization_creation", controllers.CreateOrganization)
	// USER.Get("/organization_view_by_user_id/:id", controllers.GetOrganizations)
	// USER.Get("/organization_view_by_org_id/:id", controllers.GetOrganizationByOrgID)
	// USER.Put("/organization_update_by_org_id/:id", controllers.UpdateOrganizationByOrgID)
	// USER.Delete("/organization_delete_by_org_id/:id", controllers.DeleteOrganizationByOrgID)

	// // Cause
	// USER.Post("/cause_creation", controllers.CreateCause)
	// USER.Get("/causes_view_by_user_id/:id", controllers.GetAllCauseByUserID)
	// USER.Put("/cause_update_by_id", controllers.UpdateCause)
	// USER.Delete("/cause_delete_by_cause_id/:id", controllers.DeleteCauseByCauseID)

	// // Language
	// USER.Post("/languages_creation", controllers.CreateLanguage)
	// USER.Get("/languages_view", controllers.GetLanguages)
	// USER.Get("/languages_view_by_lang_id/:id", controllers.GetLanguageByID)
	// USER.Get("/languages_view_by_user_id/:id", controllers.GetLanguageByUserID)
	// USER.Put("/languages_update_by_lang_id/:id", controllers.UpdateLanguageByID)
	// USER.Delete("/languages_delete_by_lang_id/:id", controllers.DeleteLanguage)

	// // Recommendations
	// USER.Post("/recommendation_creation", controllers.CreateRecommendation)
	// USER.Get("/recommendation_view", controllers.GetRecommendations)
	// USER.Put("/recommendation_update_by_id/:id", controllers.UpdateRecommendationByRecID)
	// USER.Delete("/recommendation_delete_by_id/:id", controllers.DeleteRecommendationByID)

	// // Featured Section
	// USER.Post("/featued_section_creation", controllers.CreateFeaturedSection)
	// USER.Get("/featued_section_view_by_user_id/:id", controllers.GetFeaturedSectionsByUserID)
	// USER.Get("/featued_section_view_by_feat_sec_id/:id", controllers.GetFeaturedSectionsByFeatSecID)
	// USER.Put("/featued_section_update_by_feat_sec_id/:id", controllers.UpdateFeaturedSectionByFeatSecID)
	// USER.Delete("/featued_section_delete_by_feat_sec_id/:id", controllers.DeleteFeaturedSectionByFeatSecID)

	// // Fetured Item
	// USER.Post("/featued_item_creation", controllers.CreateFeaturedItem)
	// USER.Get("/featued_item_view_by_user_id/:id", controllers.GetFeaturedItemByUserID)
	// USER.Get("/featued_item_view_by_feat_item_id/:id", controllers.GetFeaturedItemByFeatItemID)
	// USER.Put("/featued_item_update_by_feat_item_id/:id", controllers.UpdateFeaturedItemByFeatItemID)
	// USER.Delete("/featued_item_delete_by_feat_item_id/:id", controllers.DeleteFeaturedItemByFeatItemID)

	// // Group
	// USER.Post("/groups_creation", controllers.CreateGroup)
	// USER.Post("/groups/:groupID/join", controllers.JoinGroup)
	// USER.Post("/groups/:groupID/leave", controllers.LeaveGroup)
	// USER.Get("/groups/user/:id", controllers.GetUserGroups)

	// // Group Post
	// USER.Post("/group_post_creation", controllers.CreateGroupPost)
	// USER.Put("/group_post_update/:groupPostID", controllers.UpdateGroupPost)
	// USER.Get("/group_posts/:groupID", controllers.GetGroupPosts)
	// USER.Get("/group_post_view_by_post_id/:groupID/post/:postID", controllers.GetGroupPostByPostID)

	// 	// Group Post Comment
	// 	USER.Get("/posts/:groupPostID/comments", controllers.GetGroupPostComments)
	// 	USER.Post("/group_post_create/:groupPostID/comments", controllers.CreateGroupPostComment)
	// 	USER.Put("/posts/:groupPostID/comments/:commentID", controllers.UpdateGroupPostComment)
	// 	USER.Delete("/posts/:groupPostID/comments/:commentID", controllers.DeleteGroupPostComment)

	// 	// Notifications
	// 	USER.Get("/notifications", controllers.GetAllNotifications)
	// 	USER.Get("/user_notifications/:id", controllers.GetNotificationsHandler)
	// 	USER.Put("/notifications/read/:recipientID/:notificationID", controllers.SetNotificationAsReadHandler)
	// 	USER.Delete("/notifications/:recipientID/:notificationID", controllers.DeleteNotificationHandler)

	// 	// Group Post Like
	// 	USER.Post("/group_post_like/:groupPostID/likes", controllers.CreateGroupPostLike)
	// 	USER.Get("/group_post_like_list/:groupPostID/likes", controllers.ListGroupPostLikes)

	// 	// Group post comment replies.
	// 	USER.Post("/group_post/comment/:commentID/reply", controllers.CreateGroupPostCommentReply)
	// 	USER.Get("/group_post/comment/:commentID/replies", controllers.ViewGroupPostCommentReplies)
	// 	USER.Put("/group_post/comment/reply/:replyID", controllers.UpdateGroupPostCommentReply)
	// 	USER.Delete("/group_post/comment/reply/:replyID", controllers.DeleteGroupPostCommentReply)

	// 	// Group post comment likes.
	// 	USER.Post("/group_post/comment/:commentID/like", controllers.CreateGroupPostCommentLike)
	// 	USER.Get("/group_post/comment/:commentID/likes", controllers.ViewGroupPostCommentLikes)

	// 	// Jobs
	// 	USER.Post("/jobs_creation", controllers.CreateJob)
	// 	USER.Get("/jobs_view", controllers.GetJobs)
	// 	USER.Get("/jobs_view/:id", controllers.GetJobByJobID)
	// 	USER.Put("/jobs_update/:id", controllers.UpdateJobByJobID)
	// 	USER.Delete("/jobs_delete/:id", controllers.DeleteJobByJobID)
	// 	USER.Post("/apply_for_job/:job_id", controllers.ApplyForJobHandler)

	// 	// Message
	// 	USER.Get("/conversation_users/:id", controllers.GetConversationUsersHandler)

	// 	// Connections
	// 	USER.Post("/connect/:userID/:friendID", controllers.SendConnectionRequestHandler)
	// 	USER.Put("/connect/respond/:userID/:friendID/:status", controllers.RespondToConnectionRequestHandler)
	// 	USER.Get("/connect/:userID", controllers.GetUserConnectionsHandler)
	// 	USER.Delete("/remove_connected_user/:connectedUserID", controllers.RemoveConnectedUserHandler)

	// 	// Follower Following

	// 	USER.Post("/follow/:userID/:followerID", controllers.FollowHandler)
	// 	USER.Post("/unfollow/:userID/:followerID", controllers.UnfollowHandler)
	// 	USER.Get("/followers/:userID", controllers.GetFollowersHandler)
	// 	USER.Get("/following/:userID", controllers.GetFollowingHandler)

	// 	// Hashtags
	// 	USER.Get("/posts/:postID/hashtags", controllers.GetHashtagsByPostID)

	// 	// Normal Message
	// 	USER.Post("/create_message", controllers.SendMessageHandler)
	// 	USER.Get("/view_message/:senderID/:recipientID", controllers.GetMessagesForThreadHandler)
	// 	USER.Put("/update_message/:id", controllers.UpdateNormalMsgHandler)
	// 	USER.Delete("/delete_message/:senderID/:recipientID", controllers.DeleteNormalMsgHandler)
	// 	USER.Get("/conv_users/:id", controllers.GetConvUsersHandler)
	// 	USER.Get("/get_latest_message", controllers.GetLatestMessagesHandler)
	// 	USER.Get("/conv_users_by_url/:url", controllers.GetConvUsersWithURLHandler)

	// 	// Account Access

	// 	USER.Get("/view_email", controllers.ViewEmailByID)
	// 	USER.Put("/add_email", controllers.AddSecondaryEmail)
	// 	USER.Delete("/delete_email", controllers.RemoveEmailHandler)
	// 	// USER.Put("/change_primary_email", controllers.ChangePrimaryEmailHandler)

	// 	// USER.Put("/change_email", controllers.ChangeUserEmail)
	// 	USER.Get("/view_phone", controllers.ViewPhoneByID)
	// 	USER.Put("/add_phone", controllers.AddPhoneNumber)
	// 	USER.Put("/delete_phone", controllers.RemovePhoneNumberHandler)
	// 	USER.Put("/change_password", controllers.ChangeUserPassword)

	// 	// Visibility
	// 	USER.Get("/posts", controllers.GetAllPostsHandler)
	// 	USER.Post("/posts/toggle/", controllers.TogglePostVisibilityHandler)
	// 	USER.Get("/userpostvisibility/:user_id/:post_id", controllers.GetUserPostVisibility)

	// 	// UserProfileVisit
	// 	USER.Post("/profiles/:user_id/visit", controllers.VisitProfile)
	// 	USER.Get("/profiles/:user_id/visitor-count", controllers.GetVisitorCount)

	// 	// Repost
	// 	USER.Get("/posts/:post_id/reposts", controllers.GetRepostsForPost)
	// 	USER.Post("/posts/:post_id/repost", controllers.RepostPost)
	// 	USER.Delete("/ /:id", controllers.DeleteRepost)

	// 	// Verified
	// 	USER.Post("/verify_user", controllers.ToggleUserVerification)

}

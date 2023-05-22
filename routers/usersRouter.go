package routers

import (
	"auth/authorization"
	"auth/models"
	"auth/repositories"
	"auth/utilities"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterUsers(secure *gin.RouterGroup, userRepo *repositories.UserRepository, permissionsManager *authorization.PermissionsManager,
	tokenUtil *utilities.TokenUtil, cryptoUtil *utilities.CryptoUtil) {
	users := secure.Group("users")
	users.GET("/:userId", func(c *gin.Context) {
		requiredPermission := "View User Details"
		requestedUserId := c.Param("userId")
		authenticatedUserId, ok := c.Get("user")
		if !ok {
			log.Error().Stack().Msg("User ID not found in context")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		isAllowed, err := permissionsManager.IsAllowed(authenticatedUserId.(string), requiredPermission)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error checking user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !isAllowed {
			log.Warn().Msgf("Permissions on '%s' denied to user '%s'", requiredPermission, authenticatedUserId)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		user, err := userRepo.Select(requestedUserId)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("Error getting user info for user ID %s", requestedUserId)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, user)
	})
	users.GET("/", func(c *gin.Context) {
		requiredPermission := "user-search"
		authenticatedUser, ok := c.Get("user")
		if !ok {
			log.Error().Stack().Msg("User ID not found in context")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		isAllowed, err := permissionsManager.IsAllowed(authenticatedUser.(*models.User).UserID, requiredPermission)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error checking user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !isAllowed {
			log.Warn().Msgf("Permissions on '%s' denied to user '%s'", requiredPermission, authenticatedUser.(*models.User).UserID)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		roles := c.QueryArray("role")
		activeOnly := strings.EqualFold(c.Query("activeOnly"), "true")
		criteria := models.UserCriteria{
			Roles:      roles,
			ActiveOnly: activeOnly,
		}
		users, err := userRepo.List(&criteria)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error retrieving users")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, users)
	})
	users.POST("/", func(c *gin.Context) {
		requiredPermission := "user-create"
		authenticatedUser, ok := c.Get("user")
		if !ok {
			log.Error().Stack().Msg("User ID not found in context")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		isAllowed, err := permissionsManager.IsAllowed(authenticatedUser.(*models.User).UserID, requiredPermission)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error checking user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !isAllowed {
			log.Warn().Msgf("Permissions on '%s' denied to user '%s'", requiredPermission, authenticatedUser.(*models.User).UserID)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		requestObject := models.CreateUserRequest{}
		err = c.BindJSON(&requestObject)
		if err != nil {
			log.Warn().Err(err).Msg("Unable to bind request body to user model")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		initialPasswordHash, err := cryptoUtil.Encrypt(requestObject.InitialPassword)
		if err != nil {
			log.Error().Err(err).Msg("Error encrypting initial password")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		newUser := models.User{
			UserID:                   requestObject.UserID,
			GivenNames:               requestObject.GivenNames,
			FamilyNames:              requestObject.FamilyNames,
			Roles:                    requestObject.Roles,
			EmailAddress:             requestObject.EmailAddress,
			IsActive:                 true,
			IsPasswordChangeRequired: true,
			HashedPassword:           string(initialPasswordHash),
		}
		err = userRepo.Add(&newUser)
		if err != nil {
			log.Error().Err(err).Msg("Unable to add user")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Writer.WriteHeader(http.StatusCreated)
	})
}

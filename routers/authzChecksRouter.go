package routers

import (
	"auth/authorization"
	"auth/models"
	"auth/utilities"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterAuthzChecks(secure *gin.RouterGroup, permissionsManager *authorization.PermissionsManager, tokenUtil *utilities.TokenUtil) {
	authzChecks := secure.Group("/authz-checks")
	authzChecks.POST("", func(c *gin.Context) {
		requiredPermission := "Check for Authorization"
		authenticatedUser, ok := c.Get("user")
		if !ok {
			log.Error().Stack().Msg("User ID not found in context")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		isSubmitterAllowedToCheckPermissions, err := permissionsManager.IsAllowed(authenticatedUser.(*models.User).UserID, requiredPermission)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error checking user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !isSubmitterAllowedToCheckPermissions {
			log.Warn().Msgf("Permissions on '%s' denied to user '%s'", requiredPermission, authenticatedUser.(*models.User).UserID)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		var authzCheck models.AuthzCheck
		err = c.BindJSON(&authzCheck)
		if err != nil {
			log.Warn().Err(err).Msg("Unable to bind request body to authzCheck model")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		userId, err := tokenUtil.GetUserIdFromToken(authzCheck.BearerToken)
		if err != nil {
			log.Warn().Err(err).Msg("Unable to parse token")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		doesSubjectHavePermissions, err := permissionsManager.IsAllowed(userId, authzCheck.Permission)
		if err != nil {
			log.Error().Err(err).Msg("Failed trying to check user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, doesSubjectHavePermissions)
	})
}

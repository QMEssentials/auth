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
	authzChecks.GET("/:permission", func(c *gin.Context) {
		authenticatedUser, ok := c.Get("user")
		permission := c.Param("permission")
		if !ok {
			log.Error().Stack().Msg("User ID not found in context")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		doesSubjectHavePermissions, err := permissionsManager.IsAllowed(authenticatedUser.(*models.User).UserID, permission)
		if err != nil {
			log.Error().Err(err).Msg("Failed trying to check user permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, doesSubjectHavePermissions)
	})
}

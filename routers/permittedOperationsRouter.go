package routers

import (
	"auth/authorization"
	"auth/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterPermittedOperations(secure *gin.RouterGroup, permissionsManager *authorization.PermissionsManager) {
	permittedOperations := secure.Group("/permitted-operations")
	permittedOperations.GET(":userId", func(c *gin.Context) {
		requestedUserId := c.Param("userId")
		user, exists := c.Get("user")
		if !exists || user == nil {
			log.Warn().Msgf("User %s could not be found in the request context", requestedUserId)
		}
		if user.(*models.User).UserID != requestedUserId {
			log.Warn().Msgf("invalid attempt to get permitted operations for user %s; context user is %s", c.Param("userId"), user.(*models.User).UserID)
			c.Writer.WriteHeader(http.StatusForbidden)
			return
		}
		permittedOperations := permissionsManager.GetPermittedOperationsForRoles(user.(*models.User).Roles)
		c.JSON(http.StatusOK, permittedOperations)
	})
}

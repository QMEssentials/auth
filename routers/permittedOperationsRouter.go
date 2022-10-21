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
		user := c.Value("user").(models.User)
		if user.UserID != c.Param("userId") {
			log.Warn().Msgf("invalid attempt to get permitted operations for user %s; context user is %s", c.Param("userId"), user.UserID)
			c.Writer.WriteHeader(http.StatusForbidden)
			return
		}
		permittedOperations := permissionsManager.GetPermittedOperationsForRoles(user.Roles)
		c.JSON(http.StatusOK, permittedOperations)
	})
}

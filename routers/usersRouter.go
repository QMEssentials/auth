package routers

import (
	"auth/authorization"
	"auth/repositories"
	"auth/utilities"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterUsers(secure *gin.RouterGroup, userRepo *repositories.UserRepository, permissionsManager *authorization.PermissionsManager) {
	requiredPermission := "View User Details"
	users := secure.Group("users")
	users.GET("/:userId", func(c *gin.Context) {
		tokenUtil := utilities.NewTokenUtil()
		requestedUserId := c.Param("userId")
		authenticatedUserId, err := tokenUtil.GetUserIdFromToken(c.Param("token"))
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error getting user ID from token")
			c.Writer.WriteHeader(http.StatusInternalServerError)
		}
		isAllowed, err := permissionsManager.IsAllowed(authenticatedUserId, requiredPermission)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error checking user permissions")
			c.Writer.WriteHeader(http.StatusInternalServerError)
		}
		if !isAllowed {
			log.Warn().Msgf("Permssions on '%s' denied to user '%s'", requiredPermission, requestedUserId)
			c.Writer.WriteHeader(http.StatusForbidden)
		}
		user, err := userRepo.Select(requestedUserId)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("Error getting user info for user ID %s", requestedUserId)
			c.Writer.WriteHeader(http.StatusInternalServerError)
		}
		c.JSON(http.StatusOK, user)
	})
}

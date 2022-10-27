package routers

import (
	"auth/repositories"
	"auth/utilities"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterUserInfoForTokens(public *gin.RouterGroup, userRepo *repositories.UserRepository) {
	userInfoForTokens := public.Group("user-info-for-tokens")
	userInfoForTokens.GET("/:token", func(c *gin.Context) {
		tokenUtil := utilities.NewTokenUtil()
		userId, err := tokenUtil.GetUserIdFromToken(c.Param("token"))
		if err != nil {
			log.Error().Stack().Err(err).Msg("Error getting user ID from token")
			c.Writer.WriteHeader(http.StatusInternalServerError)
		}
		user, err := userRepo.Select(userId)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("Error getting user info for user ID %s", userId)
			c.Writer.WriteHeader(http.StatusInternalServerError)
		}
		c.JSON(http.StatusOK, user)
	})
}

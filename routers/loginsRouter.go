package routers

import (
	"auth/models"
	"auth/repositories"
	"auth/utilities"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterLogins(public *gin.RouterGroup, userRepo *repositories.UserRepository, crytpUtil *utilities.CryptoUtil,
	tokenUtil *utilities.TokenUtil) {
	logins := public.Group("/logins")
	logins.POST("", func(c *gin.Context) {
		login := models.Login{}
		err := c.BindJSON(login)
		if err != nil {
			log.Warn().Err(err).Msg("Unable to bind request body to login model")
			c.Writer.WriteHeader(http.StatusBadRequest)
			return
		}
		user, err := userRepo.Select(login.UserId)
		if err != nil {
			log.Warn().Err(err).Msgf("Error logging in as user %s", login.UserId)
			c.Writer.WriteHeader(http.StatusBadRequest)
			return
		}
		correctPassword, err := crytpUtil.Compare(login.Password, user.HashedPassword)
		if err != nil {
			log.Error().Err(err).Msgf("Error verifying password for user %s", login.UserId)
			c.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !correctPassword {
			log.Warn().Msgf("Invalid login attempt for user %s", login.UserId)
			c.Writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		token, err := tokenUtil.CreateToken(login.UserId)
		if err != nil {
			log.Error().Err(err).Msgf("Error generating token for user %s", login.UserId)
			c.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, token)
	})
}

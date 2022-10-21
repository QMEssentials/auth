package middleware

import (
	"auth/repositories"
	"auth/utilities"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterGetUserFromToken(r *gin.Engine, tokenUtil *utilities.TokenUtil, userRepo *repositories.UserRepository) {
	r.Use(func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		bearerPattern := regexp.MustCompile("(?i)^bearer (.*)$")
		tokens := bearerPattern.FindStringSubmatch(authHeader)
		if tokens == nil {
			return
		}
		if len(tokens) > 1 {
			log.Warn().Msg("Multiple bearer tokens found on request")
			c.Writer.WriteHeader(http.StatusBadRequest)
			return
		}
		userId, err := tokenUtil.GetUserIdFromToken(tokens[0])
		if err != nil {
			log.Error().Err(err).Msg("")
			c.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		user, err := userRepo.Select(userId)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		c.Set("user", user)
	})
}

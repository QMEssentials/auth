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
	handler := func() gin.HandlerFunc {
		return func(c *gin.Context) {
			authHeader := c.Request.Header.Get("Authorization")
			log.Info().Msgf("Auth header is %s", authHeader)
			bearerPattern := regexp.MustCompile("(?i)^bearer (.*)$")
			tokens := bearerPattern.FindStringSubmatch(authHeader)
			if tokens == nil {
				c.Next()
				return
			}
			userId, err := tokenUtil.GetUserIdFromToken(tokens[1])
			if err != nil {
				log.Error().Err(err).Stack().Msgf("Error getting user ID from token %s", tokens[1])
				c.Writer.WriteHeader(http.StatusUnauthorized)
				c.Abort()
				return
			}
			log.Info().Msgf("Authorization middleware found user ID '%s' in the token", userId)
			user, err := userRepo.Select(userId)
			if err != nil {
				log.Error().Err(err).Msg("")
				c.Writer.WriteHeader(http.StatusInternalServerError)
				c.Abort()
				return
			}
			log.Info().Msg("User has been retrieved and placed into context")
			c.Set("user", user)
			c.Next()
		}
	}
	r.Use(handler())
}

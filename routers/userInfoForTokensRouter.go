package routers

import (
	"auth/utilities"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RegisterUserInfoForTokens(public *gin.RouterGroup) {
	userInfoForTokens := public.Group("user-info-for-tokens")
	userInfoForTokens.GET("/:token", get)
}

func get(c *gin.Context) {
	tokenUtil := utilities.NewTokenUtil()
	token, err := tokenUtil.CreateToken(c.Param("token"))
	if err != nil {
		log.Error().Err(err).Msg("")
		c.Writer.WriteHeader(http.StatusInternalServerError)
	}
	c.JSON(http.StatusOK, token)
}

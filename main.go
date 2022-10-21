package main

import (
	"auth/authorization"
	"auth/bootstrap"
	"auth/middleware"
	"auth/repositories"
	"auth/routers"
	"auth/utilities"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

func main() {

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	mongoUtil := utilities.NewMongoUtil(utilities.GetDefaultMongoHost(), utilities.GetDefaultMongoPort())
	userRepository := repositories.NewUserRepository(mongoUtil)
	cryptoUtil := utilities.NewCryptoUtil()
	tokenUtil := utilities.NewTokenUtil()
	permissionsManger := authorization.NewPermissionsManager(userRepository)
	bootstrapper := bootstrap.NewBootstrapper(userRepository, cryptoUtil)
	err := bootstrapper.BootstrapAdminUser()
	if err != nil {
		log.Error().Stack().Err(err).Msg("")
		panic("Bootstrapping failed!")
	}

	r := gin.Default()
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "test",
		})
	})
	public := r.Group("/public")
	routers.RegisterUserInfoForTokens(public)
	routers.RegisterLogins(public, userRepository, cryptoUtil, tokenUtil)
	middleware.RegisterGetUserFromToken(r, tokenUtil, userRepository)
	secure := r.Group("/secure")
	routers.RegisterPermittedOperations(secure, permissionsManger)
	r.Run(fmt.Sprintf(":%s", os.Getenv("PORT")))
}

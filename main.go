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

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

func main() {

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	r.SetTrustedProxies(nil)
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "test",
		})
	})
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{os.Getenv("CORS_ALLOWED_ORIGIN")},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin"},
		AllowCredentials: true,
	}))
	public := r.Group("/public")
	routers.RegisterLogins(public, userRepository, cryptoUtil, tokenUtil)
	middleware.RegisterGetUserFromToken(r, tokenUtil, userRepository)
	secure := r.Group("/secure")
	routers.RegisterUsers(secure, userRepository, permissionsManger)
	routers.RegisterPermittedOperations(secure, permissionsManger)
	r.Run(fmt.Sprintf(":%s", os.Getenv("PORT")))
}

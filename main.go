package main

import (
	"auth/bootstrap"
	"auth/repositories"
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
	r.Run(fmt.Sprintf(":%s", os.Getenv("PORT")))
}

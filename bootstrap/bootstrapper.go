package bootstrap

import (
	"auth/models"
	"auth/repositories"
	"auth/utilities"
	"errors"
	"os"

	"github.com/rs/zerolog/log"
)

type Bootstrapper struct {
	userRepository *repositories.UserRepository
	cryptoUtil     *utilities.CryptoUtil
}

func NewBootstrapper(userRepository *repositories.UserRepository, cryptoUtil *utilities.CryptoUtil) *Bootstrapper {
	return &Bootstrapper{userRepository, cryptoUtil}
}

func (b *Bootstrapper) BootstrapAdminUser() error {
	userCriteria := models.UserCriteria{
		Roles:      []string{"Administrator"},
		ActiveOnly: true,
	}
	adminUsers, err := b.userRepository.List(&userCriteria)
	if err != nil {
		return err
	}
	if len(*adminUsers) > 0 {
		return nil //We've got an admin user, all good
	}
	log.Warn().Msg("No admin user found; bootstrapping new admin user with default password")
	defaultUser := os.Getenv("DEFAULT_ADMIN_USER")
	hashedPasswordBytes, err := b.cryptoUtil.Encrypt(os.Getenv("DEFAULT_ADMIN_PASSWORD"))
	if err != nil {
		return errors.New("unable to hash default password for default admin user")
	}
	user := models.User{
		UserID:                   defaultUser,
		HashedPassword:           string(hashedPasswordBytes),
		GivenNames:               []string{"Default", "Admin"},
		FamilyNames:              []string{"User"},
		IsActive:                 true,
		IsPasswordChangeRequired: false,
		Roles:                    []string{"Administrator"},
	}
	b.userRepository.Add(&user)
	return nil //New admin user created successfully
}

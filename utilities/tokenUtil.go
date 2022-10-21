package utilities

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type TokenUtil struct{}

func NewTokenUtil() *TokenUtil {
	return &TokenUtil{}
}

func (tu *TokenUtil) CreateToken(userId string) (string, error) {
	claims := jwt.MapClaims{}
	claims["iss"] = "qmessentials-auth-service"
	claims["sub"] = userId
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := rawToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (tu *TokenUtil) GetUserIdFromToken(encodedToken string) (string, error) {
	//https://pkg.go.dev/github.com/golang-jwt/jwt/v4#example-Parse-Hmac
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", nil
	}
	userId, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("unable to retrieve user ID from access token")
	}
	return userId, nil
}

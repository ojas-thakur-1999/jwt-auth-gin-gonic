package helpers

import (
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type SignedDetails struct {
	Email      string `json:"email"`
	First_name string `json:"first_name"`
	Last_name  string `json:"last_name"`
	Uid        string `json:"uid"`
	User_type  string `json:"user_type"`
	jwt.StandardClaims
}

var jwtSecret string = os.Getenv("JWT_SECRET")

func GenerateAllTokens(email string, firstName string, lastName string, userId string, userType string) (string, string) {
	tokenClaims := SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        userId,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Duration(24) * time.Hour).Unix(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims).SignedString([]byte(jwtSecret))
	if err != nil {
		log.Panic(err)
		return "", ""
	}

	refreshTokenClaims := SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Duration(168) * time.Hour).Unix(),
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims).SignedString([]byte(jwtSecret))
	if err != nil {
		log.Panic(err)
		return "", ""
	}

	return token, refreshToken
}

func ValidateToken(signedToken string) (SignedDetails, string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		},
	)
	if err != nil {
		return SignedDetails{}, err.Error()
	}

	// check if token is valid
	claims, ok := (token.Claims).(*SignedDetails)
	if !ok {
		return SignedDetails{}, "token is invalid"
	}

	// check if token is expired
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return SignedDetails{}, "token is expired"
	}

	return *claims, ""
}

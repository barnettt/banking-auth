package dto

import (
	"errors"
	"github.com/barnettt/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"time"
)

const SECRET_WORD string = "Today is good day to code"

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {
	var validationError *jwt.ValidationError
	token, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_WORD), nil
	})
	if err != nil {
		logger.Error("Unable to parse token : " + err.Error())
		if errors.As(err, &validationError) {
			return validationError
		}
	}
	// don't do this we want the expired access to ken to be refreshed.
	claimsMap := token.Claims.(jwt.MapClaims)

	if claimsMap.VerifyNotBefore(time.Now().Unix(), false) {
		validationError = jwt.NewValidationError("Token has expired", jwt.ValidationErrorExpired)
		return validationError
	}
	return nil
}

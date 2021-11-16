package domain

import (
	"banking-auth/dto"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"time"
)

const TOKEN_DURATION time.Duration = time.Hour
const REFRESH_TOKEN_TIME time.Duration = time.Hour * 24 * 30

type AuthToken struct {
	token        *jwt.Token
	refreshToken *jwt.Token
}

func NewAccessTokenFromRefreshToken(refreshToken string) (string, *exceptions.AppError) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(dto.SECRET_WORD), nil
	})
	if err != nil {
		return "", exceptions.NewUnauthorisedError("invalid or expired refresh token")
	}
	refreshTokenClaims := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := refreshTokenClaims.RefreshAccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)
	return authToken.NewAccessToken()
}

func (authToken AuthToken) NewAccessToken() (string, *exceptions.AppError) {
	token, err := authToken.token.SignedString([]byte(dto.SECRET_WORD))
	if err != nil {
		logger.Error(err.Error())
		return "", exceptions.NewJwtError("Error while attempting to sign access token")
	}
	return token, nil
}

func (authToken AuthToken) NewRefreshToken() (string, *exceptions.AppError) {
	// get the claims fpr the customer from the existing claim
	claims := authToken.token.Claims.(*AccessTokenClaims)
	refreshTokenClaims := claims.refreshTokenClaims()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	token, err := refreshToken.SignedString([]byte(dto.SECRET_WORD))
	authToken.refreshToken = refreshToken
	if err != nil {
		logger.Error(err.Error())
		return "", exceptions.NewJwtError("Error while attempting to sign refresh token")
	}
	return token, nil

}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return AuthToken{
		token: token,
	}
}

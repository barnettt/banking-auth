package service

import (
	"banking-auth/dto"
	"banking-auth/exceptions"
	"banking-auth/logger"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

type TokenService interface {
	GenerateToken(login dto.Login) (*string, *exceptions.AppError)
}

type DefaultTokenService struct {
	tokenService TokenService
}

func (serviceDefault DefaultTokenService) GenerateToken(login dto.Login) (*string, *exceptions.AppError) {
	token, err := generateToken(login)
	if err != nil {
		return nil, err
	}
	return token, nil
}

const TOKEN_DURATION time.Duration = time.Hour
const SECRET_WORD string = "Today is good day to code"

func generateToken(login dto.Login) (*string, *exceptions.AppError) {
	var claims jwt.MapClaims
	if login.AccountNumbers.Valid && login.CustomerId.Valid {
		claims = NewCustomerClaim(login)
	} else {
		claims = NewAdminClaim(login)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signTokenAsString, err := token.SignedString([]byte(SECRET_WORD))
	if err != nil {
		logger.Error(err.Error())
		return nil, exceptions.NewJwtError("Failed while signing token")
	}
	return &signTokenAsString, nil
}

func NewAdminClaim(login dto.Login) jwt.MapClaims {
	return jwt.MapClaims{
		"userName": login.UserName,
		"role":     login.Role,
		"expiry":   time.Now().Add(TOKEN_DURATION).Unix(),
	}
}

func NewCustomerClaim(login dto.Login) jwt.MapClaims {

	accounts := strings.Split(login.AccountNumbers.String, ",")
	return jwt.MapClaims{
		"customer_id": login.CustomerId.String,
		"accounts":    accounts,
		"userName":    login.UserName,
		"role":        login.Role,
		"expiry":      time.Now().Add(TOKEN_DURATION).Unix(),
	}
}

func NewTokenService() DefaultTokenService {
	return DefaultTokenService{}
}

package service

import (
	"banking-auth/domain"
	"banking-auth/dto"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

type LoginService interface {
	GenerateToken(login dto.Login) (*dto.LoginResponse, *exceptions.AppError)
}

type DefaultTokenService struct {
	loginService LoginService
	repository   domain.AuthRepositoryDB
}

func (defaultTokenService DefaultTokenService) GenerateToken(login dto.Login) (*dto.LoginResponse, *exceptions.AppError) {
	var token *domain.AuthToken
	var refreshToken string
	token, err := generateToken(login)
	if err != nil {
		return nil, err
	}
	var accessToken string
	var appErr *exceptions.AppError
	if accessToken, appErr = token.NewAccessToken(); appErr != nil {
		logger.Error(appErr.Message)
		return nil, appErr
	}

	if refreshToken, appErr = defaultTokenService.repository.GenerateAndStoreRefreshToken(token); appErr != nil {
		return nil, appErr
	}
	return &dto.LoginResponse{UserName: login.UserName, LoginTime: time.Now().Format(time.RFC3339), Token: accessToken, RefreshToken: refreshToken}, nil
}

func generateToken(login dto.Login) (*domain.AuthToken, *exceptions.AppError) {
	claims := getClaimsForAccessToken(login)
	authToken := domain.NewAuthToken(claims)
	return &authToken, nil
}

func getClaimsForAccessToken(login dto.Login) domain.AccessTokenClaims {
	if login.AccountNumbers.Valid && login.CustomerId.Valid {
		return NewCustomerClaim(login)
	} else {
		return NewAdminClaim(login)
	}
}

func NewAdminClaim(login dto.Login) domain.AccessTokenClaims {
	return domain.AccessTokenClaims{
		UserName: login.UserName,
		Role:     login.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(domain.TOKEN_DURATION).Unix(),
		},
	}
}

func NewCustomerClaim(login dto.Login) domain.AccessTokenClaims {

	accounts := strings.Split(login.AccountNumbers.String, ",")
	return domain.AccessTokenClaims{
		CustomerId: login.CustomerId.String,
		Accounts:   accounts,
		UserName:   login.UserName,
		Role:       login.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(domain.TOKEN_DURATION).Unix(),
		},
	}
}

func NewTokenService(repository domain.AuthRepositoryDB) DefaultTokenService {
	return DefaultTokenService{repository: repository}
}

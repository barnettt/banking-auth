package domain

import (
	"encoding/json"
	"errors"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"time"
)

type AccessTokenClaims struct {
	TokenType      string   `json:"token_type"`
	UserName       string   `json:"userName"`
	CustomerId     string   `json:"customer_id"`
	Role           string   `json:"role"`
	Accounts       []string `json:"accounts"`
	StandardClaims jwt.StandardClaims
}
type RefreshTokenClaims struct {
	TokenType      string   `json:"token_type"`
	Name           string   `json:"userName"`
	CId            string   `json:"customer_id"`
	Role           string   `json:"role"`
	Accounts       []string `json:"accounts"`
	StandardClaims jwt.StandardClaims
}

func HasTokenExpired(claimDate time.Time) (bool, *exceptions.AppError) {
	return validateClaimDate(claimDate)
}

func validateClaimDate(claimDate time.Time) (bool, *exceptions.AppError) {
	hour := int64(time.Hour.Minutes())
	remaining := int64(time.Now().Sub(claimDate).Minutes())
	if remaining > hour {
		return true, exceptions.NewJwtError("Token has expired")
	} else {
		return false, nil
	}
}

func (claims RefreshTokenClaims) Valid() error {
	expired, err := HasTokenExpired(time.Unix(claims.StandardClaims.ExpiresAt, 0))
	if expired {
		return errors.New(err.Message)
	}
	return nil
}
func (claims AccessTokenClaims) Valid() error {
	expired, err := HasTokenExpired(time.Unix(claims.StandardClaims.ExpiresAt, 0))
	if expired {
		return errors.New(err.Message)
	}
	return nil
}

func (claims AccessTokenClaims) refreshTokenClaims() RefreshTokenClaims {
	var date = time.Now().Add(REFRESH_TOKEN_TIME).Unix() // keep refresh token alive for 1 month
	return RefreshTokenClaims{
		TokenType: "refresh",
		Name:      claims.UserName,
		CId:       claims.CustomerId,
		Role:      claims.Role,
		Accounts:  nil,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: date,
		},
	}
}

func (claims RefreshTokenClaims) RefreshAccessTokenClaims() AccessTokenClaims {
	var date = time.Now().Add(TOKEN_DURATION).Unix()
	return AccessTokenClaims{
		TokenType:  "access",
		UserName:   claims.Name,
		CustomerId: claims.CId,
		Role:       claims.Role,
		Accounts:   claims.Accounts,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: date,
		},
	}
}

func ConvertJwtClaimsToUserClaims(claimsMap jwt.MapClaims) (*AccessTokenClaims, *exceptions.AppError) {
	// create a claims map from the jwt token by marshalling the json
	claims := make([]byte, 0)
	var err error
	if claims, err = json.Marshal(claimsMap); err != nil {
		logger.Error("Error attempting to marshal claims")
		return nil, exceptions.NewJwtError("Error attempting to marshal claims")
	}
	// convert the claims map to a AccessTokenClaims struct
	var userClaims AccessTokenClaims
	if err := json.Unmarshal(claims, &userClaims); err != nil {
		logger.Error("Error attempting to marshal claims to user claims")
		return nil, exceptions.NewJwtError("Error attempting to marshal claims to user claims")
	}

	return &userClaims, nil
}

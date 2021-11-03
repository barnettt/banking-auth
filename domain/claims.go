package domain

import (
	"banking-auth/exceptions"
	"banking-auth/logger"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"time"
)

type UserClaims struct {
	UserName   string   `json:"userName"`
	Expiry     int      `json:"expiry"`
	CustomerId string   `json:"customer_id"`
	Role       string   `json:"role"`
	Accounts   []string `json:"accounts"`
}

func (claims UserClaims) IsUserRole() bool {
	return claims.Role == "user"
}

func (claims UserClaims) IsRequestParamsVerifiedWithTokenClaims(params map[string]string) bool {
	account := params["id"]
	// example sting to int : strconv.Atoi(params["customerId"])
	if claims.CustomerId == params["customer_id"] && contains(claims.Accounts, account) {
		return true
	}

	return false
}

func (claims UserClaims) HasTokenExpired() (bool, *exceptions.AppError) {
	claimDate := time.Unix(int64(claims.Expiry), 0)
	hour := int64(time.Hour.Minutes())
	remaining := int64(time.Now().Sub(claimDate).Minutes())
	if remaining > hour {
		return true, exceptions.NewJwtError("Token has expired")
	} else {
		return false, nil
	}
}

func contains(accounts []string, account string) bool {
	for _, acc := range accounts {
		if acc == account {
			return true
		}
	}
	return false
}

func ConvertJwtClaimsToUserClaims(claimsMap jwt.MapClaims) (*UserClaims, *exceptions.AppError) {
	// create a claims map from the jwt token by marshalling the json
	claims := make([]byte, 0)
	var err error
	if claims, err = json.Marshal(claimsMap); err != nil {
		logger.Error("Error attempting to marshal claims")
		return nil, exceptions.NewJwtError("Error attempting to marshal claims")
	}
	// convert the claims map to a UserClaims struct
	var userClaims UserClaims
	if err := json.Unmarshal(claims, &userClaims); err != nil {
		logger.Error("Error attempting to marshal claims to user claims")
		return nil, exceptions.NewJwtError("Error attempting to marshal claims to user claims")
	}

	return &userClaims, nil
}

package service

import (
	"banking-auth/domain"
	"banking-auth/dto"
	"database/sql"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"strconv"
	"time"
)

type AuthService interface {
	GetUserByUserName(request dto.UserRequest) (dto.LoginResponse, error)
	RefreshToken(request dto.RefreshTokenRequest) (dto.LoginResponse, error)
}

type DefaultAuthService struct {
	repository       domain.AuthRepositoryDB
	tokenService     LoginService
	rolesPermissions domain.RolePermissions
}

func (defaultAuthService DefaultAuthService) GetUserByUserName(request dto.UserRequest) (*dto.LoginResponse, *exceptions.AppError) {
	response, err := defaultAuthService.repository.FindUser(request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, exceptions.NewDatabaseError("Error user not found")
	}
	login := dto.Login{
		UserName:       request.UserName,
		Password:       request.Password,
		Role:           response.Role,
		CustomerId:     sql.NullString{String: strconv.Itoa(response.CustomerId), Valid: true},
		AccountNumbers: sql.NullString{String: response.AccountNumbers, Valid: true},
	}
	userResponse, appErr := defaultAuthService.tokenService.GenerateToken(login)
	if appErr != nil {
		return nil, appErr
	}

	return userResponse, nil
}

func (defaultAuthService DefaultAuthService) Verify(params map[string]string) (bool, *exceptions.AppError) {
	// get a jwt token from the token string in params
	if jwtToken, err := jwtTokenFromParams(params["token"]); err != nil {
		return false, err
	} else {
		/* check that the token is valid for expiry and is a valid token*/
		if jwtToken.Valid {
			// cast the tokens claims to a  jwt.MapClaims
			claimsMap := jwtToken.Claims.(jwt.MapClaims)
			// convert the claims to a claims struct
			var claims *domain.AccessTokenClaims
			claims, err := domain.ConvertJwtClaimsToUserClaims(claimsMap)
			if err != nil {
				return false, exceptions.NewUnauthorisedError("User not authorise")
			}
			/* check the role based access against the accounts and customerId on url
			are matching the accounts and customerId in the token
			*/
			if claims.IsUserRole() {

				b := claims.IsRequestParamsVerifiedWithTokenClaims(params)
				if !b {
					return b, exceptions.NewJwtError("Forbidden bad request information ")
				}
				// check the token has not expired
				expired, err := domain.HasTokenExpired(time.Unix(claims.StandardClaims.ExpiresAt, 0))
				if expired {
					return expired, err
				}
			}
			// now check the roles and permissions allow the operation
			isAuthorised := defaultAuthService.rolesPermissions.IsAuthorisedForRole(claims.Role, params["operation"])
			return isAuthorised, nil
		}

	}
	return false, exceptions.NewJwtError("Unable to verify this request")
}

func (defaultAuthService DefaultAuthService) RefreshToken(request dto.RefreshTokenRequest) (*dto.LoginResponse, *exceptions.AppError) {
	var appErr *exceptions.AppError
	// var validationError *jwt.ValidationError
	if validationError := request.IsAccessTokenValid(); validationError != nil {
		if validationError.Errors == jwt.ValidationErrorExpired {
			if appErr = defaultAuthService.repository.DoesRefreshTokenExist(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			token, appErr := domain.NewAccessTokenFromRefreshToken(request.RefreshToken)
			if appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{
				UserName:     "",
				LoginTime:    "",
				RefreshToken: request.RefreshToken,
				Token:        token}, nil
		}
		return nil, exceptions.NewUnauthorisedError("invalid token")
	}
	return nil, exceptions.NewJwtError("cannot generate access token until current expires")
}

func jwtTokenFromParams(tokenStr string) (*jwt.Token, *exceptions.AppError) {

	logger.Info(tokenStr)
	// parse the string into a jwt token using a token function to which the secret key must be returned
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) {
		return []byte(dto.SECRET_WORD), nil
	})
	if err != nil {
		logger.Error("Error while parsing token")
		appErr := exceptions.NewValidationError("Invalid cannot parse token")
		return nil, appErr
	}
	return token, nil
}

func NewUserService(repo domain.AuthRepositoryDB, tokenService DefaultTokenService,
	rolesPermissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repository: repo, tokenService: tokenService, rolesPermissions: rolesPermissions}
}

package service

import (
	"banking-auth/domain"
	"banking-auth/dto"
	"banking-auth/exceptions"
	"banking-auth/logger"
	"database/sql"
	"github.com/golang-jwt/jwt"
	"github.com/golang-sql/civil"
	"strconv"
	"time"
)

type UserService interface {
	GetUserByUserName(request dto.UserRequest) (dto.UserResponse, error)
}

type DefaultUserService struct {
	repository       domain.UserRepositoryDB
	tokenService     domain.TokenService
	rolesPermissions domain.RolePermissions
}

func (defaultUserService DefaultUserService) GetUserByUserName(request dto.UserRequest) (*dto.UserResponse, *exceptions.AppError) {
	response, err := defaultUserService.repository.FindUser(request)
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
	token, appErr := defaultUserService.tokenService.GenerateToken(login)
	if appErr != nil {
		return nil, appErr
	}

	var dateTime = civil.DateTimeOf(time.Now())
	return &dto.UserResponse{
		UserName:  response.UserName,
		LoginTime: dateTime.String(),
		Token:     *token,
	}, nil
}

func (defaultUserService DefaultUserService) Verify(params map[string]string) (bool, *exceptions.AppError) {
	// get a jwt token from the token string in params
	if jwtToken, err := jwtTokenFromParams(params["token"]); err != nil {
		return false, err
	} else {
		/* check that the token is valid for expiry and is a valid token*/
		if jwtToken.Valid {
			// cast the tokens claims to a  map
			claimsMap := jwtToken.Claims.(jwt.MapClaims)
			// convert the claims to a claims struct
			var claims *domain.UserClaims
			claims, err := domain.ConvertJwtClaimsToUserClaims(claimsMap)
			if err != nil {
				return false, exceptions.NewJwtError("Unable to parse jwt claims")
			}
			/* check the role based access against the accounts and customerid on url
			are matching the accounts and cutomerid in the token
			*/
			if claims.IsUserRole() {

				b := claims.IsRequestParamsVerifiedWithTokenClaims(params)
				if !b {
					return b, exceptions.NewJwtError("Error bad request information ")
				}
				// check the token has not expired
				expired, err := claims.HasTokenExpired()
				if expired {
					return expired, err
				}
			}
			// now check the roles and permissions allow the operation
			isAuthorised := defaultUserService.rolesPermissions.IsAuthorisedForRole(claims.Role, params["operation"])
			return isAuthorised, nil
		}

	}
	return false, nil
}

func jwtTokenFromParams(tokenStr string) (*jwt.Token, *exceptions.AppError) {

	logger.Info(tokenStr)
	// parse the string into a jwt token using a token function to which the secret key must be returned
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) {
		return []byte(domain.SECRET_WORD), nil
	})
	if err != nil {
		logger.Error("Error while parsing token")
		appErr := exceptions.NewJwtError("Error while parsing token")
		return nil, appErr
	}
	return token, nil
}

func NewUserService(repo domain.UserRepositoryDB, tokenService domain.DefaultTokenService,
	rolesPermissions domain.RolePermissions) DefaultUserService {
	return DefaultUserService{repository: repo, tokenService: tokenService, rolesPermissions: rolesPermissions}
}

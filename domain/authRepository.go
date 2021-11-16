package domain

import (
	"banking-auth/dto"
	"database/sql"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"github.com/jmoiron/sqlx"
	"strconv"
)

type AuthRepository interface {
	FindUser(userRequest dto.UserRequest) (*User, *exceptions.AppError)
	GenerateAndStoreRefreshToken(token *AuthToken) (string, *exceptions.AppError)
	DoesRefreshTokenExist(refreshToken string) *exceptions.AppError
}
type AuthRepositoryDB struct {
	client *sqlx.DB
}

func (repository AuthRepositoryDB) GenerateAndStoreRefreshToken(token *AuthToken) (string, *exceptions.AppError) {
	// 1 generate a refresh token
	var refreshToken string
	var appErr *exceptions.AppError
	if refreshToken, appErr = token.NewRefreshToken(); appErr != nil {
		return "", appErr
	}

	// 2 store the refresh token
	insertQuery := "INSERT INTO refresh_token_store (refresh_token) VALUES (?)"
	_, err := repository.client.Exec(insertQuery, refreshToken)
	if err != nil {
		logger.Error(err.Error())
		appErr = exceptions.NewDatabaseError("Error while storing refresh token")
		return "", appErr
	}
	return refreshToken, nil
}

func (repository AuthRepositoryDB) FindUser(userRequest dto.UserRequest) (*User, *exceptions.AppError) {
	customerQuery := "SELECT username, password, role, u.customer_id, GROUP_CONCAT(a.account_id) as account_numbers " +
		"FROM USERS u  " +
		"LEFT JOIN Accounts a ON a.customer_id = u.customer_id  " +
		"where username = ? and password = ?  group by u.customer_id"

	var user User
	var accounts sql.NullString
	var customerId sql.NullString
	err := repository.client.QueryRow(customerQuery, userRequest.UserName, userRequest.Password).Scan(
		&user.UserName, &user.Password, &user.Role, &customerId, &accounts)
	if err == sql.ErrNoRows {
		anErr := exceptions.NewJwtError("invalid user credentials  user")
		return nil, anErr
	}
	if err != nil {
		logger.Error(err.Error())
		anErr := exceptions.NewDatabaseError("unable to retrieve user")
		return nil, anErr
	}
	user.AccountNumbers = accounts.String
	user.CustomerId, err = strconv.Atoi(customerId.String)
	if err != nil {
		logger.Error(err.Error())
		anErr := exceptions.NewDatabaseError("unable to convert customer id to int")
		return nil, anErr
	}
	return &user, nil
}

func (repository AuthRepositoryDB) DoesRefreshTokenExist(refreshToken string) *exceptions.AppError {
	selectQuery := "SELECT refresh_token FROM refresh_token_store where refresh_token = ?"
	var token string
	err := repository.client.Get(&token, selectQuery, refreshToken)

	if err != nil {
		if err == sql.ErrNoRows {

			return exceptions.NewJwtError("refresh token not registered")
		}
		logger.Error("Unexpected database error" + err.Error())
		return exceptions.NewDatabaseError("Unexpected database error")
	}
	return nil
}

func NewUserRepository(client *sqlx.DB) AuthRepositoryDB {
	return AuthRepositoryDB{client}
}

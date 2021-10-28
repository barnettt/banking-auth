package domain

import (
	"banking-auth/dto"
	"banking-auth/exceptions"
	"banking-auth/logger"
	"database/sql"
	"github.com/jmoiron/sqlx"
	"strconv"
)

type UserRepositoryDB struct {
	client *sqlx.DB
}

func (dbClient UserRepositoryDB) FindUser(userRequest dto.UserRequest) (*User, *exceptions.AppError) {
	customerQuery := "SELECT username, password, role, u.customer_id, GROUP_CONCAT(a.account_id) as account_numbers " +
		"FROM USERS u  " +
		"LEFT JOIN Accounts a ON a.customer_id = u.customer_id  " +
		"where username = ? and password = ?  group by u.customer_id"

	var user User
	var accounts sql.NullString
	var customerId sql.NullString
	err := dbClient.client.QueryRow(customerQuery, userRequest.UserName, userRequest.Password).Scan(
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
func NewUserRepository(client *sqlx.DB) UserRepositoryDB {
	return UserRepositoryDB{client}
}

package dto

import "database/sql"

type Login struct {
	UserName       string
	Password       string
	CustomerId     sql.NullString
	Role           string
	AccountNumbers sql.NullString
}

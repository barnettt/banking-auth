package domain

type User struct {
	UserName       string
	Password       string
	CustomerId     int `db:"customer_id"`
	Role           string
	AccountNumbers string `db:"account_numbers"`
	CreatedDate    string `db:"created_on"`
}

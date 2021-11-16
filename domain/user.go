package domain

type User struct {
	UserName       string
	Password       string
	CustomerId     int `db:"customer_id"`
	Role           string
	AccountNumbers string `db:"account_numbers"`
	CreatedDate    string `db:"created_on"`
}

func (claims AccessTokenClaims) IsUserRole() bool {
	return claims.Role == "user"
}

func (claims AccessTokenClaims) IsRequestParamsVerifiedWithTokenClaims(params map[string]string) bool {
	account := params["id"]
	// example sting to int : strconv.Atoi(params["customerId"])
	if claims.CustomerId == params["customer_id"] && contains(claims.Accounts, account) {
		return true
	}

	return false
}
func contains(accounts []string, account string) bool {
	for _, acc := range accounts {
		if acc == account {
			return true
		}
	}
	return false
}

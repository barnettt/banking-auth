package dto

//import "banking-auth/domain"

type LoginResponse struct {
	UserName     string `json:"user_name,omitempty"`
	LoginTime    string `json:"access_time,omitempty"`
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

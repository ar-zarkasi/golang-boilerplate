package response

import "time"

type TokenGenerated struct {
	Token string `json:"token"`
	Expired time.Time `json:"expired"`
}

type TokenResponse struct {
	UserId string `json:"user_id"`
	Token string `json:"token"`
	ExpiredAt string `json:"expired_at"`
	RefreshToken *string `json:"refresh_token"`
}
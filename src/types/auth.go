package types

type UserAuth struct {
	UserID       string          `json:"user_id"`
	Username     string          `json:"username"`
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	Scope        *map[string]any `json:"scope"`
	ExpireDate   string          `json:"expire_date"`
}

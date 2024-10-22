package response

type CreateUserResponse struct {
	ID    string `json:"id"`
}

type ListUserResponse struct {
	Id	string `json:"id"`
	Name string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Role string `json:"role"`
	UpdateAt string `json:"updated_at"`
}

type LoginResponse struct {
	Id	string `json:"id"`
	Name string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Role string `json:"role"`
	Token string `json:"token"`
	ExpiredToken string `json:"expired_token"`
	RefreshToken string `json:"refresh_token"`
	UpdateAt string `json:"updated_at"`
}
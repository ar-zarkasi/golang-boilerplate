package types

type ListDataRoles struct {
	RoleID    string `json:"role_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type ListDataUsers struct {
	UserID    string          `json:"user_id"`
	Email     string          `json:"email"`
	Phone     string          `json:"phone"`
	Name      string          `json:"name"`
	CreatedAt string          `json:"created_at"`
	Roles     []ListDataRoles `json:"roles"`
}

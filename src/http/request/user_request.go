package request

type CreateUserRequest struct {
	Name string `validate:"required,min=3,max=100" json:"name"`
	Email string `validate:"required,email" json:"email"`
	Phone *string `validate:"min=10,max=14" json:"phone"`
	Password string `validate:"required,min=8" json:"password"`
	RoleId uint8 `validate:"required,numeric" json:"role_id"`
	ConfirmationPassword string `validate:"required,eqfield=Password" json:"confirmation_password"`
}

type UpdateUserRequest struct {
	Name string `validate:"required,min=3,max=100" json:"name"`
	Email string `validate:"required,email" json:"email"`
	Phone *string `validate:"min=10,max=14" json:"phone"`
	RoleId uint8 `validate:"required,numeric" json:"role_id"`
}

type LoginRequest struct {
	Username string `validate:"required" json:"username"`
	Password string `validate:"required" json:"password"`
}
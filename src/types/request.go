package types

type LoginRequest struct {
	Username string  `json:"username" validate:"required"`
	Password string  `json:"password" validate:"required"`
	Metadata *string `json:"metadata" validate:"omitempty"`
}

type RegisterUserRequest struct {
	Username        *string `json:"username" validate:"omitempty,min=6,max=80"`
	Email           string  `json:"email" validate:"required_without=Phone,omitempty,email"`
	Phone           string  `json:"phone" validate:"required_without=Email,omitempty"`
	Password        string  `json:"password" validate:"required,min=6,max=50"`
	ConfirmPassword string  `json:"confirm_password" validate:"required,eqfield=Password"`
	FullName        string  `json:"full_name" validate:"required,min=3,max=160"`
	Timezone        *string `json:"timezone" validate:"omitempty,default=Asia/Jakarta"`
	Language        *string `json:"language" validate:"omitempty,default=en"`
}

type PagingCursor struct {
	LastValue   string  `json:"last_value"`
	Limit       int     `json:"limit"`
	QueryString *string `json:"query_string"`
	SortBy      *string `json:"sort_by"`
	SortOrder   *string `json:"sort_order"`
}

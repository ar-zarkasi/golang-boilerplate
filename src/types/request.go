package types

type LoginRequest struct {
	Username string  `json:"username" binding:"required"`
	Password string  `json:"password" binding:"required"`
	Metadata *string `json:"metadata" binding:"omitempty"`
}

type RegisterUserRequest struct {
	Username        *string `json:"username" binding:"omitempty,min=6,max=80"`
	Email           string  `json:"email" binding:"required_without=Phone,omitempty,email"`
	Phone           string  `json:"phone" binding:"required_without=Email,omitempty"`
	Password        string  `json:"password" binding:"required,min=6,max=50"`
	ConfirmPassword string  `json:"confirm_password" binding:"required,eqfield=Password"`
	FullName        string  `json:"full_name" binding:"required,min=3,max=160"`
	Timezone        *string `json:"timezone" binding:"omitempty"`
	Language        *string `json:"language" binding:"omitempty"`
}

type RegisterAdministratorRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=6,max=50"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}

type PagingCursor struct {
	LastValue   string        `json:"last_value"`
	Limit       int           `json:"limit"`
	QueryString []FilterQuery `json:"query_string"`
	SortBy      *string       `json:"sort_by"`
	SortOrder   *SORTING      `json:"sort_order"`
}

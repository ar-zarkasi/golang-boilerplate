package request

type CreateRoleRequest struct {
	Name string `json:"name" validate:"required"`
}
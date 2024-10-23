package services

import (
	"app/src/http/response"
	interfaces "app/src/interface"
	"app/src/models"
	"errors"
	"fmt"
)

type RoleService struct {
	RoleRepository interfaces.RoleInterface
}

func NewRoleService(RoleRepository interfaces.RoleInterface) (service *RoleService, err error) {
	return &RoleService{
		RoleRepository: RoleRepository,
	}, nil
}

func (t *RoleService) parsingModelToResponse(roles interface{}) interface{} {
	switch v := roles.(type) {
	case models.Role:
		return &response.ListRoleResponse{
			ID:       int(v.Id),
			Name:     v.Name,
		}
	case []models.Role:
		var responses []response.ListRoleResponse
		for _, role := range v {
			responses = append(responses, *&response.ListRoleResponse{
				ID:       int(role.Id),
				Name:     role.Name,
			})
		}
		return responses
	default:
		return nil
	}
}

func (t *RoleService) CreateAdminRole() (int, error) {
	var (
		role *models.Role
		IdAdmin = 1
	)
	role, err := t.RoleRepository.AdminRole()
	fmt.Println("Search Role", role)
	if err == nil {
		IdAdmin = int(role.Id)
		return IdAdmin, nil
	}
	// If Not Exists
	role, err = t.RoleRepository.CreateRole("Administrator")
	fmt.Println("Buat Role", role)
	if err == nil {
		IdAdmin = int(role.Id)
		return IdAdmin, nil
	}

	return 0, err
}

func (t *RoleService) ListRole() ([]response.ListRoleResponse, error) {
	roles, err := t.RoleRepository.FindAllRole()
	if err != nil {
		return nil, err
	}

	resp := t.parsingModelToResponse(roles).([]response.ListRoleResponse)
	return resp, nil
}

func (t *RoleService) GetRoleById(id int) *models.Role {
	role, err := t.RoleRepository.FindRoleById(uint8(id))
	if err != nil {
		return nil
	}
	return role
}

func (t *RoleService) AddRole(name string) (*int, error) {
	role, err := t.RoleRepository.CreateRole(name)
	if err != nil {
		return nil, err
	}
	id_new := int(role.Id)
	return &id_new, nil
}

func (t *RoleService) EditRole(model *models.Role, newName string) error {
	if model == nil {
		return errors.New("Role not found")
	}
	model.Name = newName
	err := t.RoleRepository.UpdateRole(*model)
	if err != nil {
		return err
	}
	return nil
}
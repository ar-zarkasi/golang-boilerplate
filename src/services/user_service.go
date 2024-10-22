package services

import (
	"app/src/http/request"
	interfaces "app/src/interface"
	"app/src/models"
	"app/utils"
	"errors"
	"os"

	"github.com/google/uuid"
)

type UserService struct {
	User interfaces.UserInterface
	Role interfaces.RoleInterface
}

func NewUserService(UserRepository interfaces.UserInterface, RoleRepository interfaces.RoleInterface) (service *UserService, err error) {
	return &UserService{
		User: UserRepository,
		Role: RoleRepository,
	}, nil
}

func (srv *UserService) CreateFirstUser() (err error) {

	var firstRole models.Role
	firstRole, err = srv.Role.AdminRole()
	if err != nil {
		idRoleAdmin, err := srv.Role.CreateAdminRole()
		if err != nil || idRoleAdmin == 0 {
			msg := "Failed to create first user"
			return errors.New(msg)
		}
		firstRole, _ = srv.Role.AdminRole()
	}

	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")

	query := map[string]interface{}{
		"email": email,
	}

	check, err := srv.User.FindUser(query)
	if err != nil {
		utils.ErrorFatal(err)
		return err
	}
	
	if len(check) > 0 {
		// skip create user
		return nil
	}
	
	model := models.User{
		Name: "Administrator",
		Email: email,
		Phone: "000000000000",
		Password: password,
		RoleId: firstRole.Id,
	}
	model.Password, err = utils.HashPassword(model.Password)
	if err != nil {
		utils.ErrorFatal(err)
		return err
	}

	err = srv.User.CreateUser(model)
	if err != nil {
		utils.ErrorFatal(err)
		return err
	}

	return nil
}

func (srv *UserService) GetAllUser() (users []models.User, err error) {
	users, err = srv.User.FindAllUser()
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (srv *UserService) GetUserById(id string) (user models.User, err error) {
	uid := uuid.MustParse(id)
	user, err = srv.User.FindUserById(uid)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (srv *UserService) GetUserByFiltering(filter map[string]interface{}) (users []models.User, err error) {
	users, err = srv.User.FindUser(filter)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (srv *UserService) AddUser(body request.CreateUserRequest) (id *string, err error) {
	user := models.User{
		Name: body.Name,
		Email: body.Email,
		Password: body.Password,
		RoleId: body.RoleId,
	}
	if body.Phone != nil {
		user.Phone = *body.Phone
	}

	user.Password, err = utils.HashPassword(user.Password)
	if err != nil {
		utils.ErrorFatal(err)
		return nil, err
	}

	err = srv.User.CreateUser(user)
	if err != nil {
		utils.ErrorFatal(err)
		return nil, err
	}
	idStr := user.Id.String()
	return &idStr, nil
}
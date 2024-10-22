package services

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/http/response"
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

func (srv *UserService) GetAllUser() (users []response.ListUserResponse, err error) {
	users_data, err := srv.User.FindAllUser()
	if err != nil {
		return nil, err
	}
	// mapping data to user response
	for _, user := range users_data {
		role, err := srv.Role.FindRoleById(user.RoleId)
		if err != nil {
			return nil, err
		}
		users = append(users, response.ListUserResponse{
			Id: user.Id.String(),
			Name: user.Name,
			Email: user.Email,
			Phone: user.Phone,
			Role: role.Name,
			UpdateAt: utils.IntDateToString(int(user.UpdatedAt)),
		})
	}
	return users, nil
}

func (srv *UserService) GetUserById(id string) (user *response.ListUserResponse, err error) {
	uid := uuid.MustParse(id)
	finder, err := srv.User.FindUserById(uid)
	if err != nil {
		return nil, err
	}
	user = &response.ListUserResponse{
		Id: finder.Id.String(),
		Name: finder.Name,
		Email: finder.Email,
		Phone: finder.Phone,
		Role: finder.Role.Name,
		UpdateAt: utils.IntDateToString(int(finder.UpdatedAt)),
	}
	return user, nil
}

func (srv *UserService) GetUserByFiltering(filter map[string]interface{}) (users []response.ListUserResponse, err error) {
	finder, err := srv.User.FindUser(filter)
	if err != nil {
		return nil, err
	}

	for _, user := range finder {
		temp := response.ListUserResponse{
			Id: user.Id.String(),
			Name: user.Name,
			Email: user.Email,
			Phone: user.Phone,
			Role: user.Role.Name,
			UpdateAt: utils.IntDateToString(int(user.UpdatedAt)),
		}
		users = append(users, temp)
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

func (srv *UserService) UpdateUser(id string, body request.UpdateUserRequest) (err error) {
	user := models.User{
		Id: uuid.MustParse(id),
		Name: body.Name,
		Email: body.Email,
		RoleId: body.RoleId,
	}
	if body.Phone != nil {
		user.Phone = *body.Phone
	}

	err = srv.User.UpdateUser(user)
	if err != nil {
		return err
	}
	return nil
}

func (srv *UserService) DeleteUser(id string) (err error) {
	uid := uuid.MustParse(id)

	err = srv.User.DeleteUser(uid)
	if err != nil {
		return err
	}
	return nil
}

func (srv *UserService) Login(body request.LoginRequest) (data *response.LoginResponse, code int, err error) {
	query := map[string]interface{}{
		"email": body.Username,
	}
	user, err := srv.User.FindUser(query)
	if err != nil {
		// checking phone
		query = map[string]interface{}{
			"phone": body.Username,
		}
		user, err = srv.User.FindUser(query)
		if err != nil {
			return nil, constant.NotFound, err
		}
	}

	user_login := user[0]

	check := utils.VerifyPassword(body.Password, user_login.Password)
	if check == false {
		return nil, constant.WrongCredential, errors.New("Password incorrect")
	}

	data = &response.LoginResponse{
		Id: user_login.Id.String(),
		Name: user_login.Name,
		Email: user_login.Email,
		Phone: user_login.Phone,
		Role: user_login.Role.Name,
		Token: "",
		ExpiredToken: "",
		RefreshToken: "",
		UpdateAt: utils.IntDateToString(int(user[0].UpdatedAt)),
	}

	return data, constant.Success, nil
}
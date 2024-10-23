package services

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/http/response"
	interfaces "app/src/interface"
	"app/src/models"
	"app/utils"
	"database/sql"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserService struct {
	User interfaces.UserInterface
	Role interfaces.RoleInterface
	Auth *interfaces.AuthInterface
	Secret *[]byte
}

func NewUserService(UserRepository interfaces.UserInterface, RoleRepository interfaces.RoleInterface, Auth *interfaces.AuthInterface) (service *UserService, err error) {
	secretKeyString := os.Getenv("SECRET_KEY")
	// If secret key is not set, use default secret key
	if secretKeyString == "" {
		secretKeyString = "GOLANG_BOILERPLATE"
	}
	secretKey := []byte(secretKeyString)

	return &UserService{
		User: UserRepository,
		Role: RoleRepository,
		Auth: Auth,
		Secret: &secretKey,
	}, nil
}

func (t *UserService) parsingModelToResponse(users interface{}) interface{} {
    switch v := users.(type) {
		case models.User:
			return &response.ListUserResponse{
				Id:       v.Id.String(),
				Name:     v.Name,
				Email:    v.Email,
				Phone:    v.Phone,
				Role:     v.Role.Name,
				UpdateAt: v.UpdatedAt.Format(constant.FORMAT_DATETIME),
			}
		case []models.User:
			var responses []response.ListUserResponse
			for _, user := range v {
				responses = append(responses, *&response.ListUserResponse{
					Id:       user.Id.String(),
					Name:     user.Name,
					Email:    user.Email,
					Phone:    user.Phone,
					Role:     user.Role.Name,
					UpdateAt: user.UpdatedAt.Format(constant.FORMAT_DATETIME),
				})
			}
			return responses
		default:
			return nil
    }
}

func (t *UserService) createToken(userId string) (*response.TokenGenerated, error) {
	expired := time.Now().Add(time.Hour * 24)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, 
        jwt.MapClaims{ 
			"userid": userId, 
			"exp": expired.Unix(), 
        })
	tokenString, err := token.SignedString(*t.Secret)
    if err != nil {
    	return nil, err
    }

 	return &response.TokenGenerated{
		Token: tokenString,
		Expired: expired,
	}, nil
}

func (srv *UserService) CreateFirstUser() (err error) {

	var firstRole models.Role
	firstRole, err = srv.Role.AdminRole()
	if err != nil {
		utils.ErrorFatal(err)
		return err
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
	users = srv.parsingModelToResponse(users_data).([]response.ListUserResponse)
	return users, nil
}

func (srv *UserService) GetUserById(id string) (user *response.ListUserResponse, err error) {
	uid := uuid.MustParse(id)
	finder, err := srv.User.FindUserById(uid)
	if err != nil {
		return nil, err
	}
	user = srv.parsingModelToResponse(finder).(*response.ListUserResponse)
	return user, nil
}

func (srv *UserService) GetUserByFiltering(filter map[string]interface{}) (users []response.ListUserResponse, err error) {
	finder, err := srv.User.FindUser(filter)
	if err != nil {
		return nil, err
	}

	users = srv.parsingModelToResponse(finder).([]response.ListUserResponse)
	return users, nil
}

func (srv *UserService) AddUser(body request.CreateUserRequest) (id *string, code int, err error) {
	user := models.User{
		Name: body.Name,
		Email: body.Email,
		Password: body.Password,
		RoleId: body.RoleId,
	}
	if body.Phone != nil {
		user.Phone = *body.Phone
	}
	// Check Role
	_, err = srv.Role.FindRoleById(user.RoleId)
	if err != nil {
		return nil, constant.NotFound, errors.New("Role not registered")
	}

	user.Password, err = utils.HashPassword(user.Password)
	if err != nil {
		return nil, constant.ServiceBroken, err
	}

	err = srv.User.CreateUser(user)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	idStr := user.Id.String()
	return &idStr, constant.SuccessCreate, nil
}

func (srv *UserService) UpdateUser(id string, body request.UpdateUserRequest) (code int, err error) {
	uid := uuid.MustParse(id)
	data, err := srv.User.FindUserById(uid)
	if err != nil {
		return constant.NotFound, err
	}
	data.Name = body.Name
	data.Email = body.Email
	data.RoleId = body.RoleId
	if body.Phone != nil {
		data.Phone = *body.Phone
	}

	err = srv.User.UpdateUser(data)
	if err != nil {
		return constant.InternalServerError, err
	}

	return constant.Success, nil
}

func (srv *UserService) DeleteUser(id string) (code int, err error) {
	uid := uuid.MustParse(id)
	err = srv.User.DeleteUser(uid)
	if err != nil {
		return constant.BadRequest, err
	}
	return constant.Success, nil
}

func (srv *UserService) prepareLogin(user_login models.User, metadata *interface{}) (data *response.LoginResponse, code int, err error) {
	data_user := srv.parsingModelToResponse(user_login).(*response.ListUserResponse)
	data = &response.LoginResponse{
		Id: data_user.Id,
		Name: data_user.Name,
		Email: data_user.Email,
		Phone: data_user.Phone,
		RoleId: int(user_login.RoleId),
		Role: data_user.Role,
		Token: "",
		ExpiredToken: "",
		RefreshToken: "",
		UpdateAt: data_user.UpdateAt,
	}
	// creating new token
	token, err := srv.createToken(data.Id)
	if err != nil {
		return nil, constant.InternalServerError, err
	}

	// creating new refresh token
	refreshToken, err := srv.createToken(data.Id)
	if err != nil {
		return nil, constant.InternalServerError, err
	}

	new_token, err := (*srv.Auth).Signin(user_login, token.Token, &token.Expired, metadata)
	data.Token = new_token.Token
	data.ExpiredToken = new_token.ExpiredAt
	data.RefreshToken = refreshToken.Token

	// Updating Data
	user_login.RefreshToken = sql.NullString{String: refreshToken.Token, Valid: true}
	user_login.RefreshTokenExpiredAt = sql.NullTime{Time: refreshToken.Expired, Valid: true}
	err = srv.User.UpdateUser(user_login)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	data.UpdateAt = user_login.UpdatedAt.String()

	return data, constant.Success, nil
}

func (srv *UserService) Login(body request.LoginRequest, metadata *interface{}) (data *response.LoginResponse, code int, err error) {
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

	// check if has already login
	check_login, err := (*srv.Auth).FindTokenByUserId(user_login.Id.String())
	if err == nil && len(check_login) > 0 {
		return srv.pastLogin(check_login)
	}

	return srv.prepareLogin(user_login, metadata)
}

func (srv *UserService) pastLogin(check []models.Authentication) (data *response.LoginResponse, code int, err error) {
	skip := 0
	lengthAuth := len(check)
	user := check[0].User
	for _, login := range check {
		// check if token is still valid
		if login.ExpiredAt.Time.After(time.Now()) {
			data_user := srv.parsingModelToResponse(login.User).(*response.ListUserResponse)
			data = &response.LoginResponse{
				Id: data_user.Id,
				Name: data_user.Name,
				Email: data_user.Email,
				Phone: data_user.Phone,
				RoleId: int(login.User.RoleId),
				Role: data_user.Role,
				Token: login.Token,
				ExpiredToken: login.ExpiredAt.Time.Format(constant.FORMAT_DATETIME),
				RefreshToken: login.User.RefreshToken.String,
				UpdateAt: data_user.UpdateAt,
			}
			return data, constant.Success, nil
		}
		(*srv.Auth).DeleteToken(login)	
		skip++;
	}
	
	if skip == lengthAuth {
		return srv.prepareLogin(user, nil)
	}

	return nil, constant.WrongCredential, errors.New("Token expired")
}

func (srv *UserService) VerifyToken(tokenString string) (*models.User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	   return *srv.Secret, nil
	})
	if err != nil {
	   return nil, err
	}
	if !token.Valid {
	   return nil, errors.New("Token is not valid")
	}

	userId := token.Claims.(jwt.MapClaims)["userid"].(string)
	modelUser, err := srv.User.FindUserById(uuid.MustParse(userId))
	if err != nil {
		return nil, err
	}

	return &modelUser, nil
 }

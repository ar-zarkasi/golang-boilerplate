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
	Auth interfaces.AuthInterface
	Secret *[]byte
}

func NewUserService(UserRepository interfaces.UserInterface, RoleRepository interfaces.RoleInterface, Auth interfaces.AuthInterface) (service *UserService, err error) {
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

func (t *UserService) parsingModelToResponse(users models.User) *response.ListUserResponse {
    return &response.ListUserResponse{
		Id: users.Id.String(),
		Name: users.Name,
		Email: users.Email,
		Phone: users.Phone,
		Role: users.Role.Name,
		UpdateAt: users.UpdatedAt.String(),
	}
}

func (srv *UserService) CreateFirstUser(email string, password string) (err error) {

	var firstRole *models.Role
	firstRole, err = srv.Role.AdminRole()
	if err != nil {
		utils.ErrorFatal(err)
		return err
	}

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
	users = make([]response.ListUserResponse, 0)
	for _, user := range users_data {
		users = append(users, *srv.parsingModelToResponse(user))
	}
	return users, nil
}

func (srv *UserService) GetUserById(id string) (user *response.ListUserResponse, err error) {
	uid := uuid.MustParse(id)
	finder, err := srv.User.FindUserById(uid)
	if err != nil {
		return nil, err
	}
	user = srv.parsingModelToResponse(*finder)
	return user, nil
}

func (srv *UserService) GetUserByFiltering(filter map[string]interface{}) (users []response.ListUserResponse, err error) {
	finder, err := srv.User.FindUser(filter)
	if err != nil {
		return nil, err
	}

	users = make([]response.ListUserResponse, 0)
	for _, user := range finder {
		users = append(users, *srv.parsingModelToResponse(user))
	}
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

	// Check same user email has registered before
	query := map[string]interface{}{
		"email": user.Email,
	}
	listUser, err := srv.User.FindUser(query)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	if len(listUser) > 0 {
		return nil, constant.ValidationError, errors.New("User already registered")
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

	err = srv.User.UpdateUser(*data)
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

func (srv *UserService) Login(body request.LoginRequest, metadata *interface{}) (data *response.LoginResponse, code int, err error) {
	query := map[string]interface{}{
		"email": body.Username,
	}
	users, err := srv.User.FindUser(query)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	if len(users) == 0 {
		return nil, constant.NotFound, errors.New("User not found")
	}

	user := users[0]
	if !utils.VerifyPassword(body.Password, user.Password) {
		return nil, constant.Unauthorized, errors.New("Wrong Credential")
	}

	resp := response.LoginResponse{
		Id: user.Id.String(),
		Name: user.Name,
		Email: user.Email,
		Phone: user.Phone,
		Role: user.Role.Name,
		Token: "",
		ExpiredToken: "",
		RefreshToken: user.RefreshToken.String,
		RoleId: int(user.RoleId),
		UpdateAt: user.UpdatedAt.String(),
	}

	checkHasLogin, err := srv.Auth.FindTokenByUserId(user.Id.String())
	if err == nil && len(checkHasLogin) > 0 {
		for _, authenticate := range checkHasLogin {
			if authenticate.ExpiredAt.Time.After(time.Now()) {
				resp.Token = authenticate.Token
				resp.ExpiredToken = authenticate.ExpiredAt.Time.Format(constant.FORMAT_DATETIME)
				break
			}
		}
		return &resp, constant.Success, nil
	}

	expired := time.Now().Add(time.Hour * 24)
	datatoken := map[string]interface{}{"userid": user.Id.String(), "exp": expired.Unix()}
	token, err := utils.GenerateToken(datatoken, &expired)
	if err != nil {
		return nil, constant.InternalServerError, err
	}

	resp.Token = token.Token
	resp.ExpiredToken = token.Expired.Format(constant.FORMAT_DATETIME)

	// regenerate refresh token
	refreshToken, err := utils.GenerateToken(user, nil)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	resp.RefreshToken = user.RefreshToken.String
	user.RefreshToken = sql.NullString{ String: refreshToken.Token, Valid: true}
	user.RefreshTokenExpiredAt = sql.NullTime{Time: refreshToken.Expired, Valid: true}

	err = srv.User.UpdateUser(user)
	if err != nil {
		return nil, constant.InternalServerError, err
	}
	resp.UpdateAt = user.UpdatedAt.String()

	// Record Login
	err = srv.Auth.Signin(user.Id.String(), resp.Token, &token.Expired, metadata)
	if err != nil {
		return nil, constant.InternalServerError, err
	}

	return &resp, constant.Success, nil
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

	return modelUser, nil
 }

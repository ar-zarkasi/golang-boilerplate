package testing

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/http/response"
	"app/src/models"
	"app/src/services"
	"app/testing/mocking"
	"app/utils"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"math/rand"

	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type UserServiceTest struct {
	user mocking.UserRepositoryMock
	roles mocking.RoleRepositoryMock
	auth mocking.AuthRepositoryMock
	services services.UserService
}

func NewTestUserService() *UserServiceTest {
	return &UserServiceTest{
		user: mocking.UserRepositoryMock{}, 
		roles: mocking.RoleRepositoryMock{}, 
		auth: mocking.AuthRepositoryMock{}, 
		services: services.UserService{
			User: &mocking.UserRepositoryMock{},
			Role: &mocking.RoleRepositoryMock{},
			Auth: &mocking.AuthRepositoryMock{},
		},
	}
}

// SetupTest ensures a fresh setup for each test
func (R *UserServiceTest) SetupTest(t *testing.T) {
    R.user.Db = &mock.Mock{}  // Reset the mock
    R.roles.Db = &mock.Mock{}  // Reset the mock
	R.auth.Db = &mock.Mock{}  // Reset the mock
	service, _ := services.NewUserService(&R.user, &R.roles, &R.auth)
    R.services = *service  // Reinitialize the service
}

func TestUserService(t *testing.T) {
	serverTest := NewTestUserService()
	if serverTest == nil {
		fmt.Println("Error", errors.New("User Service is not defined"))
		t.FailNow()
	}
	t.Run("TestCreateFirstUser", serverTest.TestCreateFirstUser)
	t.Run("TestGetAllUser", serverTest.TestGetAllUser)
	t.Run("TestGetUserById", serverTest.TestGetUserById)
	t.Run("TestGetUserByFiltering", serverTest.TestGetUserByFiltering)
	t.Run("TestAddUser", serverTest.TestAddUser)
	t.Run("TestUpdateUser", serverTest.TestUpdateUser)
	t.Run("TestDeleteUser", serverTest.TestDeleteUser)
	t.Run("TestLoginWithEmail", serverTest.TestLoginEmailSuccess)
}

func (R *UserServiceTest) TestCreateFirstUser(t *testing.T) {
	R.SetupTest(t)
	role := models.Role{ Id: uint8(1), Name: "Administrator" }
	R.roles.Db.On("AdminRole").Return(role, nil)

	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	passwordEncrypted, err := utils.HashPassword(password)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	uidFirstCreate := "00000000-0000-0000-0000-000000000000"
	usermodel := models.User{
		Id: uuid.MustParse(uidFirstCreate),
		Name: "Administrator",
		Email: email,
		Phone: "000000000000",
		Password: passwordEncrypted,
		RoleId: role.Id,
	}

	query := map[string]interface{}{
		"email": email,
	}

	listUser := make([]models.User, 0)

	R.user.Db.On("FindUser", query).Return(listUser, nil)
	R.user.Db.On("CreateUser", usermodel).Return(nil)
	err = R.services.CreateFirstUser(usermodel.Email, usermodel.Password)
	assert.Nil(t, err)
	assert.Equal(t, true, utils.VerifyPassword(password, usermodel.Password))
}

func (R *UserServiceTest) TestGetAllUser(t *testing.T) {
	R.SetupTest(t)
	listModel := make([]models.User, 0)
	roles := []uint8{1, 2, 3}
	for i := 0; i < 5; i++ {
		randomroles := roles[rand.Intn(len(roles))]
		user := models.User{
			Id: uuid.New(),
			Name: faker.Name(),
			Email: faker.Email(),
			Phone: faker.PhoneNumber,
			Password: faker.Password(),
			RoleId: randomroles,
		}
		encPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		user.Password = encPassword
		listModel = append(listModel, user)
	}
	R.user.Db.On("FindAllUser").Return(listModel, nil)
	lists, err := R.services.GetAllUser()
	assert.Nil(t, err)
	for i, v := range lists {
		assert.Equal(t, listModel[i].Name, v.Name)
		assert.Equal(t, listModel[i].Email, v.Email)
		assert.Equal(t, listModel[i].Phone, v.Phone)
		assert.Equal(t, listModel[i].Id.String(), v.Id)
	}
}

func (R *UserServiceTest) TestGetUserById(t *testing.T) {
	R.SetupTest(t)
	roles := []uint8{1, 2, 3}
	randomroles := roles[rand.Intn(len(roles))]
	user := models.User{
		Id: uuid.New(),
		Name: faker.Name(),
		Email: faker.Email(),
		Phone: faker.PhoneNumber,
		Password: faker.Password(),
		RoleId: randomroles,
	}
	encPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	user.Password = encPassword
	R.user.Db.On("FindUserById", user.Id).Return(user, nil)
	l, err := R.services.GetUserById(user.Id.String())
	assert.Nil(t, err)
	assert.Equal(t, user.Name, l.Name)
	assert.Equal(t, user.Email, l.Email)
	assert.Equal(t, user.Phone, l.Phone)
	assert.Equal(t, user.Id.String(), l.Id)
}

func (R *UserServiceTest) TestGetUserByFiltering(t *testing.T) {
	R.SetupTest(t)
	roles := []uint8{1, 2, 3}
	phone := faker.PhoneNumber
	listUser := make([]models.User, 0)
	for i := 0; i < 2; i++ {
		randomroles := roles[rand.Intn(len(roles))]
		user := models.User{
			Id: uuid.New(),
			Name: faker.Name(),
			Email: faker.Email(),
			Phone: phone,
			Password: faker.Password(),
			RoleId: randomroles,
		}
		user.Password, _ = utils.HashPassword(user.Password)
		listUser = append(listUser, user)
	}

	query := map[string]interface{}{
		"phone": phone,
	}
	R.user.Db.On("FindUser", query).Return(listUser, nil)
	l, err := R.services.GetUserByFiltering(query)
	assert.Nil(t, err)
	for i, v := range l {
		assert.Equal(t, listUser[i].Name, v.Name)
		assert.Equal(t, listUser[i].Email, v.Email)
		assert.Equal(t, listUser[i].Phone, v.Phone)
		assert.Equal(t, listUser[i].Id.String(), v.Id)
	}
}

func (R *UserServiceTest) TestAddUser(t *testing.T){
	R.SetupTest(t)
	role := models.Role{ Id: uint8(2), Name: "Public" }
	R.roles.Db.On("AdminRole").Return(role, nil)

	password := faker.Password()
	passwordEncrypted, err := utils.HashPassword(password)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	phone := faker.PhoneNumber
	requestData := request.CreateUserRequest{
		Name: faker.Name(),
		Email: faker.Email(),
		Phone: &phone,
		Password: passwordEncrypted,
		ConfirmationPassword: passwordEncrypted,
		RoleId: role.Id,
	}

	
	uidFirstCreate := "00000000-0000-0000-0000-000000000000"
	usermodel := models.User{
		Id: uuid.MustParse(uidFirstCreate),
		Name: requestData.Name,
		Email: requestData.Email,
		Phone: *requestData.Phone,
		Password: requestData.Password,
		RoleId: role.Id,
	}

	query := map[string]interface{}{
		"email": usermodel.Email,
	}

	listUser := make([]models.User, 0)

	R.roles.Db.On("FindRoleById", role.Id).Return(role, nil)
	R.user.Db.On("FindUser", query).Return(listUser, nil)
	R.user.Db.On("CreateUser", usermodel).Return(nil)
	idNew, code, err := R.services.AddUser(requestData)
	
	assert.Nil(t, err)
	assert.NotNil(t, idNew)
	assert.Equal(t, constant.SuccessCreate, code)
}

func (R *UserServiceTest) TestUpdateUser(t *testing.T) {
	R.SetupTest(t)
	
	roles := []uint8{1, 2, 3}
	randomroles := roles[rand.Intn(len(roles))]
	user := models.User{
		Id: uuid.New(),
		Name: faker.Name(),
		Email: faker.Email(),
		Phone: faker.PhoneNumber,
		Password: faker.Password(),
		RoleId: randomroles,
	}
	encPassword, _ := utils.HashPassword(user.Password)
	user.Password = encPassword
	R.user.Db.On("FindUserById", user.Id).Return(user, nil)

	randomroles = roles[rand.Intn(len(roles))]
	phoneChange := faker.PhoneNumber
	updaterequest := request.UpdateUserRequest{
		Name: faker.Name(),
		Email: faker.Email(),
		Phone: &phoneChange,
		RoleId: randomroles,
	}

	userAfterUpdate := models.User{
		Id: user.Id,
		Name: updaterequest.Name,
		Email: updaterequest.Email,
		Password: user.Password,
		Phone: phoneChange,
		RoleId: updaterequest.RoleId,
	}

	R.user.Db.On("UpdateUser", userAfterUpdate).Return(nil)
	code, err := R.services.UpdateUser(user.Id.String(), updaterequest)
	assert.Nil(t, err)
	assert.Equal(t, constant.Success, code)
}

func (R *UserServiceTest) TestDeleteUser(t *testing.T) {
	R.SetupTest(t)
	roles := []uint8{1, 2, 3}
	randomroles := roles[rand.Intn(len(roles))]
	encPassword, _ := utils.HashPassword(faker.Password())
	user := models.User{
		Id: uuid.New(),
		Name: faker.Name(),
		Email: faker.Email(),
		Phone: faker.PhoneNumber,
		Password: encPassword,
		RoleId: randomroles,
	}

	R.user.Db.On("FindUserById", user.Id).Return(user, nil)
	R.user.Db.On("DeleteUser", user.Id).Return(nil)
	code, err := R.services.DeleteUser(user.Id.String())
	assert.Nil(t, err)
	assert.Equal(t, constant.Success, code)
}

func (R *UserServiceTest) TestLoginEmailSuccess(t *testing.T) {
	R.SetupTest(t)
	
	var metadata *interface{} = nil

	roles := 1
	role := models.Role{ Id: uint8(roles), Name: "Administrator" }
	requestBody := request.LoginRequest{
		Username: faker.Email(),
		Password: faker.Password(),
	}
	passwordEncrypted, _ := utils.HashPassword(requestBody.Password)
	user := models.User{
		Id: uuid.New(),
		Name: faker.Name(),
		Email: requestBody.Username,
		Phone: faker.TollFreePhoneNumber(),
		Password: passwordEncrypted,
		RoleId: role.Id,
		Role: role,
	}

	listUser := make([]models.User, 0)
	listUser = append(listUser, user)

	query := map[string]interface{}{
		"email": user.Email,
	}
	R.user.Db.On("FindUser",query).Return(listUser, nil)
	checkPassword := utils.VerifyPassword(requestBody.Password, user.Password)
	assert.Equal(t, true, checkPassword)

	// Check if user has already login, no need generate new token
	auths := make([]models.Authentication, 0)
	R.auth.Db.On("FindTokenByUserId", user.Id.String()).Return(auths, assert.AnError)

	timeProvider := &mocking.MockTimeProvider{}

	expired := timeProvider.Now()
	storedData := map[string]interface{}{
		"userid": user.Id.String(),
		"exp": expired.Unix(),
	}
	token, _ := utils.GenerateToken(storedData, &expired)
	assert.NotNil(t, token)
	
	loginResponse := response.LoginResponse{
		Id: user.Id.String(),
		Name: user.Name,
		Email: user.Email,
		Phone: user.Phone,
		RoleId: int(user.RoleId),
		Role: user.Role.Name,
		Token: token.Token,
		ExpiredToken: token.Expired.Format(constant.FORMAT_DATETIME),
		RefreshToken: "",
		UpdateAt: user.UpdatedAt.Format(constant.FORMAT_DATETIME),
	}


	expiredRefresh := expired.Add(time.Hour * 24 * 30)
	datatokenRefresh := map[string]interface{}{"userid": user.Id.String(), "email": user.Email}
	refreshToken, _ := utils.GenerateToken(datatokenRefresh, &expiredRefresh)
	assert.NotNil(t, refreshToken)

	loginResponse.RefreshToken = refreshToken.Token
	user.RefreshToken = sql.NullString{ String: refreshToken.Token, Valid: true }
	user.RefreshTokenExpiredAt = sql.NullTime{ Time: refreshToken.Expired, Valid: true }
	R.user.Db.On("UpdateUser", user).Return(nil)
	loginResponse.UpdateAt = user.UpdatedAt.Format(constant.FORMAT_DATETIME)

	R.auth.Db.On("Signin", user.Id.String(), token.Token, &expired, metadata).Return(nil)
	LoggedIn, code, err := R.services.Login(requestBody, metadata, &expired)
	assert.Nil(t, err)
	assert.Equal(t, constant.Success, code)
	assert.Equal(t, loginResponse.Id, LoggedIn.Id)
	assert.Equal(t, loginResponse.Token, LoggedIn.Token)
}
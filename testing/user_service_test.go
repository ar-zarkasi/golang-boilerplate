package testing

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/models"
	"app/src/services"
	"app/utils"
	"errors"
	"fmt"
	"os"
	"testing"

	"math/rand"

	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type UserServiceTest struct {
	user UserRepositoryMock
	roles RoleRepositoryMock
	auth AuthRepositoryMock
	services services.UserService
}

func NewTestUserService() *UserServiceTest {
	Repo := &UserRepositoryMock{Db: &mock.Mock{}}
	RepoRole := &RoleRepositoryMock{Db: &mock.Mock{}}
	RepoAuth := &AuthRepositoryMock{Db: &mock.Mock{}}
	RepoAuthInterface := NewAuthMock(RepoAuth.Db)
	service, _ := services.NewUserService(Repo, RepoRole, &RepoAuthInterface)
	return &UserServiceTest{user: *Repo, roles: *RepoRole, auth: *RepoAuth, services: *service}
}

// SetupTest ensures a fresh setup for each test
func (R *UserServiceTest) SetupTest(t *testing.T) {
    R.user.Db = &mock.Mock{}  // Reset the mock
    R.roles.Db = &mock.Mock{}  // Reset the mock
	R.auth.Db = &mock.Mock{}  // Reset the mock
	authInterface := NewAuthMock(R.auth.Db)
	service, _ := services.NewUserService(&R.user, &R.roles, &authInterface)
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
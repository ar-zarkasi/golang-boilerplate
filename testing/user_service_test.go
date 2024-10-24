package testing

import (
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
package testing

import (
	"app/src/models"
	"app/src/services"
	"errors"
	"fmt"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)


type RoleServiceTest struct {
	repository RoleRepositoryMock
	services  services.RoleService
}

func NewTestRoleService() *RoleServiceTest {
	Repo := &RoleRepositoryMock{Db: &mock.Mock{}}
	RepoMock := RoleRepositoryMock{Db: Repo.Db}
	service, _ := services.NewRoleService(Repo)
	return &RoleServiceTest{repository: RepoMock, services: *service}
}

func TestMain(t *testing.T) {
	serverTest := NewTestRoleService()
	if serverTest == nil {
		fmt.Println("Error", errors.New("Role Service is not defined"))
		t.FailNow()
	}

	// fmt.Println("Role Service Test", serverTest.repository, serverTest.services)
	t.Run("TestCreateAdmin", serverTest.TestCreateAdmin)
	t.Run("TestCreateAdminExists", serverTest.TestCreateAdminExists)
	t.Run("TestGetListRole", serverTest.TestGetListRole)
	t.Run("TestGetListRoleEmpty", serverTest.TestGetListRoleEmpty)
	t.Run("TestGetRoleById", serverTest.TestGetRoleById)
	t.Run("TestGetRoleByIdNotFound", serverTest.TestGetRoleByIdNotFound)
	t.Run("TestCreateRole", serverTest.TestCreateRole)
	t.Run("TestCreateRoleError", serverTest.TestCreateRoleError)
	t.Run("TestCreateRoleNotSame", serverTest.TestCreateRoleNotSame)
	t.Run("TestUpdateRole", serverTest.TestUpdateRole)
	t.Run("TestUpdateRoleError", serverTest.TestUpdateRoleError)
}

// SetupTest ensures a fresh setup for each test
func (R *RoleServiceTest) SetupTest(t *testing.T) {
    R.repository.Db = &mock.Mock{}  // Reset the mock
	service, _ := services.NewRoleService(&R.repository)
    R.services = *service  // Reinitialize the service
}

func (R RoleServiceTest) TestCreateAdmin(t *testing.T) {
	R.SetupTest(t);

	role := models.Role{
		Id:   uint8(1),
		Name: "Administrator",
	}
	
	R.repository.Db.On("AdminRole").Return(nil, assert.AnError)
	R.repository.Db.On("CreateRole", role.Name).Return(role, nil)
	result, err := R.services.CreateAdminRole()
	fmt.Println("Result", result, role.Id)
	assert.Equal(t, role.Id, uint8(result))
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestCreateAdminExists(t *testing.T) {
	R.SetupTest(t);

	role := models.Role{
		Id:   uint8(1),
		Name: "Administrator",
	}

	R.repository.Db.On("AdminRole").Return(role, nil)
	result, err := R.services.CreateAdminRole()
	assert.Equal(t, role.Id, uint8(result))
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestGetListRole(t *testing.T) {
	R.SetupTest(t);

	roles := make([]models.Role, 0)
	for i := 0; i < 5; i++ {
		roles = append(roles, models.Role{
			Id:   uint8(i+1),
			Name: faker.Name(),
		})
	}
	R.repository.Db.On("FindAllRole").Return(roles, nil)
	result, err := R.services.ListRole()
	assert.Equal(t, len(roles), len(result))
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestGetListRoleEmpty(t *testing.T) {
	R.SetupTest(t);

	roles := make([]models.Role, 0)
	R.repository.Db.On("FindAllRole").Return(roles, nil)
	result, err := R.services.ListRole()
	assert.Equal(t, len(roles), len(result))
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestGetRoleById(t *testing.T) {
	R.SetupTest(t);

	role := models.Role{
		Id:   uint8(1),
		Name: "Administrator",
	}

	R.repository.Db.On("FindRoleById", role.Id).Return(role, nil)
	result := R.services.GetRoleById(int(role.Id))
	assert.Equal(t, role.Id, result.Id)
	assert.Equal(t, role.Name, result.Name)
}

func (R RoleServiceTest) TestGetRoleByIdNotFound(t *testing.T) {
	R.SetupTest(t);

	role := models.Role{}

	R.repository.Db.On("FindRoleById", role.Id).Return(role, assert.AnError)
	result := R.services.GetRoleById(int(role.Id))
	assert.Nil(t, result)
}

func (R RoleServiceTest) TestCreateRole(t *testing.T) {
	R.SetupTest(t);

	randomIds, _ := faker.RandomInt(1, 100)
	randomId := randomIds[0]
	role := models.Role{
		Id:   uint8(randomId),
		Name: faker.Name(),
	}

	R.repository.Db.On("CreateRole", role.Name).Return(role, nil)
	result, err := R.services.AddRole(role.Name)
	assert.Equal(t, role.Id, uint8(*result))
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestCreateRoleError(t *testing.T) {
	R.SetupTest(t);
	name := faker.Name()

	R.repository.Db.On("CreateRole", name).Return(nil, assert.AnError)
	result, err := R.services.AddRole(name)
	assert.Nil(t, result)
	assert.Error(t, err)
}

func (R RoleServiceTest) TestCreateRoleNotSame(t *testing.T) {
	R.SetupTest(t);

	randomIds, _ := faker.RandomInt(1, 100)
	randomId := randomIds[0]
	role := models.Role{
		Id:   uint8(randomId),
		Name: faker.Name(),
	}
	expectedId := uint8(randomIds[5])

	R.repository.Db.On("CreateRole", role.Name).Return(role, nil)
	result, err := R.services.AddRole(role.Name)
	assert.NotEqual(t, int(expectedId), result)
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestUpdateRole(t *testing.T) {
	R.SetupTest(t);

	randomIds, _ := faker.RandomInt(1, 100)
	randomId := randomIds[0]

	role := models.Role{
		Id:   uint8(randomId),
		Name: faker.Name(),
	}

	changeName := faker.Name()
	role.Name = changeName

	R.repository.Db.On("UpdateRole", role).Return(nil)
	err := R.services.EditRole(&role, changeName)
	assert.Nil(t, err)
}

func (R RoleServiceTest) TestUpdateRoleError(t *testing.T) {
	R.SetupTest(t);

	changeName := faker.Name()

	var role *models.Role
	role = nil

	R.repository.Db.On("UpdateRole", role).Return(assert.AnError)
	err := R.services.EditRole(role, changeName)
	assert.NotNil(t, err)
	assert.Error(t, err)
}
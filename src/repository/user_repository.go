package repository

import (
	interfaces "app/src/interface"
	"app/src/middleware"
	"app/src/models"
	helper "app/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository struct {
	Db *gorm.DB
	with []string
}

func NewUser(db *gorm.DB) (interfaces.UserInterface) {
	return &UserRepository{Db: db, with: []string{"Role", "Login"}}
}

func (t *UserRepository) loadEager() *gorm.DB {
	db := t.Db
	for _, v := range t.with {
		db = db.Preload(v)
	}
	return db
}

func (t *UserRepository) notAdmin(db *gorm.DB) {
	// if Accessing user is not admin, filter out admin role
	activeUser := middleware.GetUserActive()
	adminId := uint8(1)
	if activeUser == nil || activeUser.Role.Id != adminId {
		db = db.Where("role_id <> ?", adminId)
	}
}

func (t *UserRepository) FindAllUser() ([]models.User, error) {
	var users []models.User
	db := t.loadEager()
	t.notAdmin(db)
	result := db.Where("deleted_at IS NULL").Order("created_at ASC").Find(&users)
	return users, result.Error
}

func (t *UserRepository) FindUserById(id uuid.UUID) (*models.User, error) {
	var user models.User
	db := t.loadEager()
	result := db.First(&user, "id = ?", id)
	return &user, result.Error
}

func (t *UserRepository) FindUser(filter map[string]interface{}) ([]models.User, error) {
	var users []models.User
	tempdb := t.loadEager()
	likeColumn := []string{"name", "email", "phone"}
	for key, value := range filter {
		if helper.ContainString(likeColumn, key) {
			if strValue, ok := value.(string); ok {
				tempdb.Where(key+" LIKE ?", "%"+strValue+"%")
			}
			continue
		}
		tempdb.Where(key, value)
	}
	result := tempdb.Find(&users)
	return users, result.Error
}

func (t *UserRepository) CreateUser(user models.User) error {
	result := t.Db.Create(&user)
	return result.Error
}

func (t *UserRepository) UpdateUser(user models.User) error {
	result := t.Db.Save(&user)
	return result.Error
}

func (t *UserRepository) DeleteUser(id uuid.UUID) error {
	model, err := t.FindUserById(id)
	if err != nil {
		return err
	}
	result := t.Db.Delete(&model)
	return result.Error
}
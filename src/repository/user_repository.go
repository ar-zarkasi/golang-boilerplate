package repository

import (
	interfaces "app/src/interface"
	"app/src/models"
	helper "app/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository struct {
	Db *gorm.DB
}

func NewUser(db *gorm.DB) (interfaces.UserInterface) {
	return &UserRepository{Db: db}
}

func (t *UserRepository) FindAllUser() ([]models.User, error) {
	var users []models.User
	result := t.Db.Where("deleted_at IS NULL").Order("created_at ASC").Find(&users)
	return users, result.Error
}

func (t *UserRepository) FindUserById(id uuid.UUID) (models.User, error) {
	var user models.User
	result := t.Db.First(&user, "id = ?", id)
	return user, result.Error
}

func (t *UserRepository) FindUser(filter map[string]interface{}) ([]models.User, error) {
	var users []models.User
	tempdb := t.Db
	likeColumn := []string{"name", "email", "phone"}
	for key, value := range filter {
		if helper.ContainString(likeColumn, key) {
			tempdb.Where(key+" LIKE %?%", value)
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
	result := t.Db.Delete(&models.User{}, "id = ?", id)
	return result.Error
}
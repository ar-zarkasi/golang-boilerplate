package repository

import (
	interfaces "app/src/interface"
	"app/src/middleware"
	"app/src/models"
	"app/utils"
	helper "app/utils"

	"gorm.io/gorm"
)

type RoleRepository struct {
	Db *gorm.DB
	with []string
}

func NewRole(db *gorm.DB) (interfaces.RoleInterface) {
	return &RoleRepository{Db: db, with: []string{"Users"}}
}

func (t *RoleRepository) loadEager(db *gorm.DB) *gorm.DB {
	for _, v := range t.with {
		db = t.Db.Preload(v)
	}
	return db
}

func (t *RoleRepository) notAdmin(db *gorm.DB) {
	// if Accessing user is not admin, filter out admin role
	activeUser := middleware.GetUserActive()
	AdminRole, err := t.AdminRole()
	if err != nil {
		utils.ErrorFatal(err)
		return
	}
	if activeUser == nil || activeUser.Role.Id != AdminRole.Id {
		db = db.Where("id <> ?", AdminRole.Id)
	}
}

func (t *RoleRepository) FindAllRole() ([]models.Role, error) {
	var roles []models.Role
	db := t.loadEager(t.Db)
	t.notAdmin(db)
	result := db.Find(&roles)
	return roles, result.Error
}

func (t *RoleRepository) FindRoleById(id uint8) (models.Role, error) {
	var role models.Role
	db := t.loadEager(t.Db)
	result := db.First(&role, id)
	return role, result.Error
}

func (t *RoleRepository) FindRole(filter map[string]interface{}) ([]models.Role, error) {
	var roles []models.Role
	tempdb := t.loadEager(t.Db)
	likeColumn := []string{"name"}
	for key, value := range filter {
		if helper.ContainString(likeColumn, key) {
			tempdb.Where(key+" LIKE ?", "%"+value.(string)+"%")
			continue
		}
		tempdb.Where(key, value)
	}
	result := tempdb.Find(&roles)
	return roles, result.Error
}

func (t *RoleRepository) CreateRole(name string) (*models.Role, error) {
	role := models.Role{Name: name}
	result := t.Db.Create(&role)
	return &role, result.Error
}

func (t *RoleRepository) UpdateRole(role models.Role) error {
	result := t.Db.Save(&role)
	return result.Error
}

func (t *RoleRepository) DeleteRole(id uint8) error {
	model, err := t.FindRoleById(id)
	if err != nil {
		return err
	}
	result := t.Db.Delete(&model, id)
	return result.Error
}

func (t *RoleRepository) AdminRole() (models.Role, error) {
	var (
		role models.Role
		adminId = 1 //preserved for admin role
	)
	db := t.loadEager(t.Db)
	result := db.First(&role, adminId)
	return role, result.Error
}
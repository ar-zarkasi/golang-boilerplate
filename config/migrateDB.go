package config

import (
	"app/src/repository"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gorm.io/gorm"
)

// Function to migrate models
func MigrateModels(db *gorm.DB, modelsPath string) {
    files, err := os.ReadDir(modelsPath)
    if err != nil {
        panic(err)
    }

    for _, file := range files {
        if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") {
            continue
        }

        pkgPath := filepath.Join(modelsPath, file.Name())
        importPath := strings.TrimSuffix(pkgPath, ".go")

        modelType := reflect.TypeOf(importPath)
        if modelType.Kind() == reflect.Struct {
            db.AutoMigrate(reflect.New(modelType).Interface())
        }
    }
}
// Function to migrate models each entity
func MigrateEntityModels(db *gorm.DB, entities ...interface{}) {
    for _, entity := range entities {
        db.AutoMigrate(entity)
    }
}
// Function to Init Repository
func InitRepository(db *gorm.DB) []interface{} {

    UserRepository := repository.NewUser(db)
    RoleRepository := repository.NewRole(db)

    return []interface{}{&UserRepository, &RoleRepository}

}
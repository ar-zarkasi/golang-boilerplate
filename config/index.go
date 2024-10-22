package config

import (
	"os"
	"strconv"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"
)

var (
	globalDb *gorm.DB = nil
	mongodb *mongo.Database = nil
	globalValidator = validator.New()
)

func init() {
	useDB := os.Getenv("DB_CLIENT")
	if useDB == "postgres" {
		runPostgres()
	} else {
		runMysql()
	}

	useMongo, err := strconv.ParseBool(os.Getenv("USE_MONGO"))
	if err == nil {
		if useMongo {
			runMongo()
		}
	}
}

func GetActiveDB() *gorm.DB {
	return globalDb
}

func GetValidator() *validator.Validate {
	return globalValidator
}
package config

import (
	"app/src/models"
	"app/utils"
	"fmt"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func runPostgres() {
	globalDb = connectPostgres()
	MigrateEntityModels(globalDb, &models.Role{}, &models.User{}, &models.Authentication{})
}

func connectPostgres() *gorm.DB {
	// connect to PostgreSql
	var (
		host = os.Getenv("DB_HOST")
		user = os.Getenv("DB_USER")
		password = os.Getenv("DB_PASSWORD")
		dbname = os.Getenv("DB_NAME")
		port = os.Getenv("DB_PORT")
		timezone = os.Getenv("DB_TIMEZONE")
	)

	// set default timezone if not set
	if timezone == "" {
		timezone = "Asia/Jakarta"
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=%s",host,user,password,dbname,port,timezone)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	utils.ErrorFatal(err)

	return db
}

func getDBPostgres() *gorm.DB {
	return globalDb
}
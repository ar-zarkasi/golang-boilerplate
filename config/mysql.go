package config

import (
	"app/utils"
	"fmt"
	"os"

	"app/src/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func runMysql() {
	globalDb = connectMysql()
	MigrateEntityModels(globalDb, &models.Role{}, &models.User{}, &models.Authentication{})
}

func connectMysql() *gorm.DB {
	// connect to mysql
	var (
		host = os.Getenv("DB_HOST")
		user = os.Getenv("DB_USER")
		password = os.Getenv("DB_PASSWORD")
		dbname = os.Getenv("DB_NAME")
		port = os.Getenv("DB_PORT")
	)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",user,password,host,port,dbname)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	utils.ErrorFatal(err)

	return db
}

func GetMysql() *gorm.DB {
	return globalDb
}


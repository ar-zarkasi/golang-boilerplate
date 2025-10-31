package connections

import (
	"app/src/models"
	"app/src/types"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Database interface {
	DB() *gorm.DB
	Close() error
	Ping() error
	Migration() error
}

type gormWrapper struct {
	db *gorm.DB
}

func initPostgreDatabase(cfg types.MainConfig) Database {
	config := cfg.Database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		config.Host, config.User, config.Password, config.DBName, config.Port,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to PostgreSQL DB: %v", err)
	}

	return &gormWrapper{db: db}
}

func initMySQLDatabase(cfg types.MainConfig) Database {
	config := cfg.Database
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.User, config.Password, config.Host, config.Port, config.DBName,
	)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to Mysql DB: %v", err)
	}

	return &gormWrapper{db: db}
}

func initSqliteDatabase(cfg types.MainConfig) Database {
	config := cfg.Database
	dbPath := config.DBName

	// Get the directory path
	dbDir := filepath.Dir(dbPath)

	// Check if directory exists, create if it doesn't
	if dbDir != "" && dbDir != "." {
		if _, err := os.Stat(dbDir); os.IsNotExist(err) {
			log.Printf("Creating database directory: %s", dbDir)
			if err := os.MkdirAll(dbDir, 0755); err != nil {
				log.Fatalf("failed to create database directory: %v", err)
			}
		}
	}

	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Printf("Database file not found, creating new SQLite database: %s", dbPath)
		// Create the file
		file, err := os.Create(dbPath)
		if err != nil {
			log.Fatalf("failed to create database file: %v", err)
		}
		file.Close()
	} else {
		log.Printf("Using existing SQLite database: %s", dbPath)
	}

	dsn := fmt.Sprintf("%s?cache=shared&mode=rwc", dbPath)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to SQLite DB: %v", err)
	}

	return &gormWrapper{db: db}
}

func NewDatabase(cfg types.MainConfig) Database {
	switch cfg.Database.Type {
	case types.DBTypePostgres:
		return initPostgreDatabase(cfg)
	case types.DBTypeMySQL:
		return initMySQLDatabase(cfg)
	case types.DBTypeSQLite:
		return initSqliteDatabase(cfg)
	default:
		log.Fatalf("unsupported database type: %s", cfg.Database.Type)
		return nil
	}
}

func (g *gormWrapper) DB() *gorm.DB {
	return g.db
}

func (g *gormWrapper) Ping() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func (g *gormWrapper) Close() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (g *gormWrapper) Migration() error {
	// Run auto migration first
	err := g.db.AutoMigrate(models.GetAllModels()...)
	if err != nil {
		return err
	}
	return nil
	// Run any custom migrations that require safe column operations
	// return models.Migrations(g.db)
}

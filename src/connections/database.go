package connections

import (
	"app/src/constants"
	"app/src/models"
	"app/src/types"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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

// getGormLogger returns a GORM logger configured based on GIN_MODE
// Development: logs to stdout with Info level
// Release: logs to daily file with Warn level
func getGormLogger() logger.Interface {
	var logWriter io.Writer
	var logLevel logger.LogLevel

	ginMode := os.Getenv("GIN_MODE")

	if ginMode == "release" {
		// Production: log to file with Warn level (only errors and warnings)
		logsDir := "logs"
		os.MkdirAll(logsDir, 0755)
		logFileName := filepath.Join(logsDir, "database-"+time.Now().Format(constants.FORMAT_DATE)+".log")
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("Failed to open database log file, using stdout: %v", err)
			logWriter = os.Stdout
		} else {
			logWriter = logFile
		}
		logLevel = logger.Warn
	} else {
		// Development: log to stdout with Info level (all queries)
		logWriter = os.Stdout
		logLevel = logger.Info
	}

	return logger.New(
		log.New(logWriter, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logLevel,
			IgnoreRecordNotFoundError: true,
			Colorful:                  ginMode != "release",
		},
	)
}

func initPostgreDatabase(cfg types.MainConfig) Database {
	config := cfg.Database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		config.Host, config.User, config.Password, config.DBName, config.Port,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: getGormLogger(),
	})
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
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: getGormLogger(),
	})
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
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: getGormLogger(),
	})
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
}

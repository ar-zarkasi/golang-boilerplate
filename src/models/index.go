package models

import (
	"fmt"

	"gorm.io/gorm"
)

func GetAllModels() []interface{} {
	return []interface{}{
		&Role{},
		&User{},
		&UserSession{},
		&UserProfile{},
		&UserRole{},
	}
}

func SafeDropColumn(db *gorm.DB, tableName, columnName string) error {
	// Check if column exists before attempting to drop
	var exists bool
	err := db.Raw("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = ? AND column_name = ?)", tableName, columnName).Scan(&exists).Error
	if err != nil {
		return fmt.Errorf("failed to check column existence: %w", err)
	}

	if !exists {
		return nil // Column doesn't exist, nothing to drop
	}

	// Use raw SQL for more reliable column dropping
	return db.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s", tableName, columnName)).Error
}

func SafeAddColumn(db *gorm.DB, tableName, columnName, columnType string) error {
	if db.Migrator().HasColumn(tableName, columnName) {
		return nil // Column already exists, nothing to add
	}
	return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, columnName, columnType)).Error
}

func SafeRenameColumn(db *gorm.DB, tableName, oldColumn, newColumn string) error {
	if !db.Migrator().HasColumn(tableName, oldColumn) {
		return nil // Old column doesn't exist, nothing to rename
	}
	if db.Migrator().HasColumn(tableName, newColumn) {
		return nil // New column already exists, nothing to rename
	}
	return db.Migrator().RenameColumn(tableName, oldColumn, newColumn)
}

func SafeModifyColumn(db *gorm.DB, tableName, columnName, newType string) error {
	if !db.Migrator().HasColumn(tableName, columnName) {
		return fmt.Errorf("column %s does not exist in table %s", columnName, tableName)
	}
	return db.Exec(fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s TYPE %s", tableName, columnName, newType)).Error
}

func Migrations(db *gorm.DB) error {
	// Get all table names from our models
	tables := map[string]interface{}{
		"roles":         &Role{},
		"users":         &User{},
		"user_sessions": &UserSession{},
		"user_profiles": &UserProfile{},
		"user_roles":    &UserRole{},
	}

	// Clean up obsolete columns automatically
	for tableName, model := range tables {
		err := cleanupObsoleteColumns(db, tableName, model)
		if err != nil {
			return fmt.Errorf("failed to cleanup obsolete columns for table %s: %w", tableName, err)
		}
	}

	return nil
}

func cleanupObsoleteColumns(db *gorm.DB, tableName string, model interface{}) error {
	// Get existing columns from database
	var dbColumns []string
	err := db.Raw(`
		SELECT column_name 
		FROM information_schema.columns 
		WHERE table_name = ? 
		AND table_schema = current_schema()
	`, tableName).Scan(&dbColumns).Error
	if err != nil {
		return fmt.Errorf("failed to get database columns: %w", err)
	}

	// Get model field names using GORM
	stmt := &gorm.Statement{DB: db}
	err = stmt.Parse(model)
	if err != nil {
		return fmt.Errorf("failed to parse model: %w", err)
	}

	// Create set of model columns (including GORM standard fields)
	modelColumns := make(map[string]bool)
	for _, field := range stmt.Schema.Fields {
		modelColumns[field.DBName] = true
	}

	// Add standard GORM fields that might not be in the parsed schema
	standardFields := []string{"id", "created_at", "updated_at", "deleted_at"}
	for _, field := range standardFields {
		modelColumns[field] = true
	}

	// Drop columns that exist in DB but not in model
	for _, dbColumn := range dbColumns {
		if !modelColumns[dbColumn] {
			err := SafeDropColumn(db, tableName, dbColumn)
			if err != nil {
				return fmt.Errorf("failed to drop obsolete column %s: %w", dbColumn, err)
			}
		}
	}

	return nil
}

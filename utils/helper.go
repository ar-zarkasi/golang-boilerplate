package utils

import (
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func ContainString(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func IntDateToString(date int) string {
	timezone := os.Getenv("TZ")
	dateString := time.Unix(int64(date), 0).In(time.FixedZone(timezone, 0))
	return dateString.Format(time.RFC3339)
}

// HashPassword generates a bcrypt hash for the given password.
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
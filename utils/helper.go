package utils

import "golang.org/x/crypto/bcrypt"

func ContainString(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
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
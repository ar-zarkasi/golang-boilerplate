package utils

import (
	httpResponse "app/src/http/response"
	"os"
	"time"

	"math/rand"

	"github.com/golang-jwt/jwt/v5"
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

func PickRandomInterface(arr []interface{}) interface{} {
	return arr[rand.Intn(len(arr))]
}

func GenerateToken(data interface{}, expired *time.Time) (*httpResponse.TokenGenerated, error) {
	secretKeyString := os.Getenv("SECRET_KEY")
	if secretKeyString == "" {
		secretKeyString = "GOLANG_BOILERPLATE"
	}
	secretKey := []byte(secretKeyString)

	if expired == nil {
		exp := time.Now().Add(time.Hour * 24)
		expired = &exp
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, 
		jwt.MapClaims{"data": data})
	tokenString, err := token.SignedString(secretKey)
    if err != nil {
    	return nil, err
    }

 	return &httpResponse.TokenGenerated{
		Token: tokenString,
		Expired: *expired,
	}, nil
}
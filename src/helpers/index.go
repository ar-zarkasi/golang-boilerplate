package helpers

import (
	"app/src/connections"
	"app/src/models"
	"app/src/types"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type HelperInterface interface {
	MakeRequest(method string, url string, params any) ([]byte, error)
	GetLastHeaderResponse() *http.Header
	GetLastStatusCode() int
	InitializeSystem() error
	GetDatabase() connections.Database
	GetKafka() connections.Kafka
	GetRabbitMQ() connections.RabbitMQ
	GetS3Client() connections.S3Client
	SetCache(key string, value any, ttl int) error
	GetCache(key string) (*string, error)
	DeleteCache(key string) error
	LoadConfig(conf any) error
	FindProjectRoot() (string, error)
	GetDefaultLimitData() int
	ErrorFatal(err error)
	ErrorResponse(context *gin.Context, code int, message string)
	ErrorMessage(code int) string
	GetStringValue(ptr *string) string
	GetBoolValue(ptr *bool) string
	JSONToStruct(data []byte, v interface{}) error
	StructToJSON(v interface{}) ([]byte, error)
	SendResponse(ctx *gin.Context, response types.ResponseDefault)
	GenerateRandomLabel(prefix string, n int) string
	FormatSize(bytes int64) string
	Encrypt(plaintext []byte, key string) (string, error)
	Decrypt(ciphertextBase64 string, key string) ([]byte, error)
	Unpad(src []byte) []byte
	ZeroUnpad(data []byte) []byte
	GetMainConfig() types.MainConfig
	SetTokenActive(token string)
	GetTokenActive() string
	SetUserActive(user models.User)
	GetUserActive() models.User
	SetUserToken(token string)
	GetUserToken() string
	IsFileComplete(filePath string) bool
	ReadJSONFile(filePath string, target interface{}) error
	HashPassword(password string) (string, error)
	VerifyPassword(hashedPassword, password string) bool
	GenerateSecureToken(length int) (string, error)
	LoadTimeLocale(locale string) *time.Location
	NormalizePhone(phonestring string) string
	DefaultValue(ptr *string, defaultValue string) string
	GetTimeProvider() TimeProvider
	CheckValidationRequest(ctx *gin.Context, request any) error
}

type Helpers struct {
	timeProvider TimeProvider
}

func NewHelpers() HelperInterface {
	return &Helpers{
		timeProvider: &DefaultTimeProvider{},
	}
}

package mocks

import (
	"app/src/connections"
	"app/src/helpers"
	"app/src/models"
	"app/src/types"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
)

// MockHelperInterface is a mock implementation of helpers.HelperInterface
type MockHelperInterface struct {
	mock.Mock
}

func (m *MockHelperInterface) IsProduction() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockHelperInterface) SetBaseUrl(url string) {
	m.Called(url)
}
func (m *MockHelperInterface) GetBaseUrl() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockHelperInterface) MakeRequest(method string, url string, params any) ([]byte, error) {
	args := m.Called(method, url, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockHelperInterface) GetLastHeaderResponse() *http.Header {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*http.Header)
}

func (m *MockHelperInterface) GetLastStatusCode() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockHelperInterface) InitializeSystem() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockHelperInterface) GetDatabase() connections.Database {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(connections.Database)
}

func (m *MockHelperInterface) GetKafka() connections.Kafka {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(connections.Kafka)
}

func (m *MockHelperInterface) GetRabbitMQ() connections.RabbitMQ {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(connections.RabbitMQ)
}

func (m *MockHelperInterface) GetS3Client() connections.S3Client {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(connections.S3Client)
}

func (m *MockHelperInterface) SetCache(key string, value any, ttl int) error {
	args := m.Called(key, value, ttl)
	return args.Error(0)
}

func (m *MockHelperInterface) GetCache(key string) (*string, error) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*string), args.Error(1)
}

func (m *MockHelperInterface) DeleteCache(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockHelperInterface) DeleteCachePattern(pattern string) error {
	args := m.Called(pattern)
	return args.Error(0)
}

func (m *MockHelperInterface) LoadConfig(conf any) error {
	args := m.Called(conf)
	return args.Error(0)
}

func (m *MockHelperInterface) FindProjectRoot() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockHelperInterface) GetDefaultLimitData() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockHelperInterface) ErrorFatal(err error) {
	m.Called(err)
}

func (m *MockHelperInterface) ErrorResponse(context *gin.Context, code int, message string) {
	m.Called(context, code, message)
}

func (m *MockHelperInterface) ErrorMessage(code int) string {
	args := m.Called(code)
	return args.String(0)
}

func (m *MockHelperInterface) GetStringValue(ptr *string) string {
	args := m.Called(ptr)
	return args.String(0)
}

func (m *MockHelperInterface) GetBoolValue(ptr *bool) string {
	args := m.Called(ptr)
	return args.String(0)
}

func (m *MockHelperInterface) JSONToStruct(data []byte, v interface{}) error {
	args := m.Called(data, v)
	return args.Error(0)
}

func (m *MockHelperInterface) StructToJSON(v interface{}) ([]byte, error) {
	args := m.Called(v)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockHelperInterface) InterfaceToStruct(data any, v interface{}) error {
	args := m.Called(data, v)
	return args.Error(0)
}

func (m *MockHelperInterface) SendResponse(ctx *gin.Context, response types.ResponseDefault) {
	m.Called(ctx, response)
}

func (m *MockHelperInterface) SendResponseData(ctx *gin.Context, code int, message string, data any) {
	m.Called(ctx, code, message, data)
}

func (m *MockHelperInterface) GenerateRandomLabel(prefix string, n int) string {
	args := m.Called(prefix, n)
	return args.String(0)
}

func (m *MockHelperInterface) FormatSize(bytes int64) string {
	args := m.Called(bytes)
	return args.String(0)
}

func (m *MockHelperInterface) Encrypt(plaintext []byte, key *string) (string, error) {
	args := m.Called(plaintext, key)
	return args.String(0), args.Error(1)
}

func (m *MockHelperInterface) Decrypt(ciphertextBase64 string, key *string) ([]byte, error) {
	args := m.Called(ciphertextBase64, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockHelperInterface) Unpad(src []byte) []byte {
	args := m.Called(src)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]byte)
}

func (m *MockHelperInterface) ZeroUnpad(data []byte) []byte {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]byte)
}

func (m *MockHelperInterface) GetMainConfig() types.MainConfig {
	args := m.Called()
	return args.Get(0).(types.MainConfig)
}

func (m *MockHelperInterface) SetTokenActive(token string) {
	m.Called(token)
}

func (m *MockHelperInterface) GetTokenActive() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockHelperInterface) SetUserActive(user models.User) {
	m.Called(user)
}

func (m *MockHelperInterface) GetUserActive() models.User {
	args := m.Called()
	return args.Get(0).(models.User)
}

func (m *MockHelperInterface) SetUserToken(token string) {
	m.Called(token)
}

func (m *MockHelperInterface) GetUserToken() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockHelperInterface) IsFileComplete(filePath string) bool {
	args := m.Called(filePath)
	return args.Bool(0)
}

func (m *MockHelperInterface) ReadJSONFile(filePath string, target interface{}) error {
	args := m.Called(filePath, target)
	return args.Error(0)
}

func (m *MockHelperInterface) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockHelperInterface) VerifyPassword(hashedPassword, password string) bool {
	args := m.Called(hashedPassword, password)
	return args.Bool(0)
}

func (m *MockHelperInterface) GenerateSecureToken(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockHelperInterface) LoadTimeLocale(locale string) *time.Location {
	args := m.Called(locale)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*time.Location)
}

func (m *MockHelperInterface) NormalizePhone(phonestring string) string {
	args := m.Called(phonestring)
	return args.String(0)
}

func (m *MockHelperInterface) DefaultValue(ptr *string, defaultValue string) string {
	args := m.Called(ptr, defaultValue)
	return args.String(0)
}

func (m *MockHelperInterface) GetTimeProvider() helpers.TimeProvider {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(helpers.TimeProvider)
}

func (m *MockHelperInterface) GenerateJWTToken(payLoad any, expires time.Time) (string, error) {
	args := m.Called(payLoad, expires)
	return args.String(0), args.Error(1)
}

func (m *MockHelperInterface) ParsingJWT(token string, payload interface{}) error {
	args := m.Called(token, payload)
	return args.Error(0)
}

func (m *MockHelperInterface) FormatValidationError(err error) string {
	args := m.Called(err)
	return args.String(0)
}

func (m *MockHelperInterface) SetupLogging() {
	m.Called()
}

func (m *MockHelperInterface) ContainString(s, substr string) bool {
	args := m.Called(s, substr)
	return args.Bool(0)
}

func (m *MockHelperInterface) ConvertStringToInt64(s string) int64 {
	args := m.Called(s)
	return args.Get(0).(int64)
}

func (m *MockHelperInterface) Slugify(text string) string {
	args := m.Called(text)
	return args.String(0)
}

func (m *MockHelperInterface) ConvertInt64ToString(i int64) string {
	args := m.Called(i)
	return args.String(0)
}

func (m *MockHelperInterface) ValidateSafeHTML(value string) error {
	args := m.Called(value)
	return args.Error(0)
}

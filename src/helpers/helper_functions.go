package helpers

import (
	"app/src/connections"
	"app/src/constants"
	"app/src/models"
	"app/src/types"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	tokenActive        string
	userActive         models.User
	tokenUser          string
	lastStatusCode     int
	lastHeaderResponse *http.Header
	baseURL            string
	databaseInstance   connections.Database
	redisClient        connections.Redis
	kafkaInstance      connections.Kafka
	amqpInstance       connections.RabbitMQ
	s3Client           connections.S3Client
)

func (h *Helpers) IsProduction() bool {
	release := os.Getenv("GIN_MODE")
	return release == "release"
}
func (h *Helpers) SetBaseUrl(url string) {
	baseURL = url
}
func (h *Helpers) MakeRequest(method string, url string, params any) ([]byte, error) {
	client := &http.Client{}

	var (
		req    *http.Request
		err    error
		Config types.MainConfig
	)

	err = h.LoadConfig(&Config)
	if err != nil {
		return nil, err
	}

	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	if params == nil {
		req, err = http.NewRequest(method, baseURL+url, nil)
	} else {
		jsonData, _ := h.StructToJSON(params)
		if strings.ToLower(method) == "get" {
			req, err = http.NewRequest(method, baseURL+url, nil)
			q := req.URL.Query()
			mapping := map[string]any{}
			h.JSONToStruct(jsonData, &mapping)
			for key, value := range mapping {
				if value != nil && value != "" {
					if m, ok := value.(map[string]interface{}); ok {
						for k, v := range m {
							keyattr := strings.ToLower(key) + "[" + k + "]"
							valparam := fmt.Sprintf("%s", v)
							if m, ok := v.(int64); ok {
								valparam = fmt.Sprintf("%d", m)
							} else if m, ok := v.(float64); ok {
								valparam = fmt.Sprintf("%d", int(m))
							}
							q.Add(keyattr, valparam)
						}
					} else {
						if m, ok := value.(int64); ok {
							q.Add(strings.ToLower(key), fmt.Sprintf("%d", m))
						} else if m, ok := value.(float64); ok {
							q.Add(strings.ToLower(key), fmt.Sprintf("%d", int(m)))
						} else if m, ok := value.([]string); ok {
							q.Add(strings.ToLower(key), strings.Join(m, ","))
						} else if m, ok := value.([]interface{}); ok {
							stringParams := []string{}
							for _, v := range m {
								if m, ok := v.(string); ok {
									stringParams = append(stringParams, m)
								}
							}
							q.Add(strings.ToLower(key), strings.Join(stringParams, ","))
						} else {
							q.Add(strings.ToLower(key), fmt.Sprintf("%s", value))
						}
					}
				}
			}
			req.URL.RawQuery = q.Encode()
			req.Header.Add("Content-Type", "application/json")
		} else {
			// json data to form data
			var formData bytes.Buffer
			writer := multipart.NewWriter(&formData)
			mapping := map[string]any{}
			h.JSONToStruct(jsonData, &mapping)
			for key, value := range mapping {
				if value != nil && value != "" {
					if m, ok := value.(int64); ok {
						writer.WriteField(strings.ToLower(key), fmt.Sprintf("%d", m))
					} else if m, ok := value.(float64); ok {
						writer.WriteField(strings.ToLower(key), fmt.Sprintf("%d", int(m)))
					} else if m, ok := value.([]string); ok {
						writer.WriteField(strings.ToLower(key), strings.Join(m, ","))
					} else if m, ok := value.([]interface{}); ok {
						stringParams := []string{}
						for _, v := range m {
							if m, ok := v.(string); ok {
								stringParams = append(stringParams, m)
							}
						}
						writer.WriteField(strings.ToLower(key), strings.Join(stringParams, ","))
					} else {
						writer.WriteField(strings.ToLower(key), fmt.Sprintf("%s", value))
					}
				}
			}
			err = writer.Close()
			if err != nil {
				return nil, err
			}
			req, err = http.NewRequest(method, baseURL+url, &formData)
			req.Header.Add("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
		}
	}

	if err != nil {
		return nil, err
	}

	// add authorization if token exists
	token := h.GetTokenActive()
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}
	log.Printf("URL Full Request %s\n", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	lastHeaderResponse = &resp.Header
	lastStatusCode = resp.StatusCode
	return body, nil
}
func (h *Helpers) GetLastHeaderResponse() *http.Header {
	return lastHeaderResponse
}
func (h *Helpers) GetLastStatusCode() int {
	return lastStatusCode
}
func (h *Helpers) InitializeSystem() error {
	config := h.GetMainConfig()
	var err error = nil
	// init databases
	databaseInstance = connections.NewDatabase(config)
	if databaseInstance == nil {
		return fmt.Errorf("failed to initialize database")
	}
	err = databaseInstance.Migration()
	if err != nil {
		return fmt.Errorf("failed to run database migration: %w", err)
	}
	// init redis
	redisClient = connections.NewRedis(config)
	if redisClient == nil {
		return fmt.Errorf("failed to initialize Redis")
	}
	// init message broker
	log.Printf("Initializing message broker: %s\n", config.MessageBroker.Provider)
	switch config.MessageBroker.Provider {
	case types.BrokerTypeKafka:
		kafkaInstance, err = connections.NewKafka(config)
		if err == nil {
			log.Println("Kafka initialized successfully")
		}
	case types.BrokerTypeRabbitMQ:
		amqpInstance, err = connections.NewRabbitMQ(config)
		if err == nil {
			log.Println("RabbitMQ initialized successfully")
		}
	default:
		log.Println("Not Using Message Broker [DONE]")
	}

	if config.S3.Provider != "" {
		s3Client, err = connections.NewS3Client(config)
	}

	return err
}
func (h *Helpers) GetDatabase() connections.Database {
	return databaseInstance
}
func (h *Helpers) GetKafka() connections.Kafka {
	return kafkaInstance
}
func (h *Helpers) GetRabbitMQ() connections.RabbitMQ {
	return amqpInstance
}
func (h *Helpers) GetS3Client() connections.S3Client {
	return s3Client
}
func (h *Helpers) SetCache(key string, value any, ttl int) error {
	data, err := h.StructToJSON(value)
	if err != nil {
		return err
	}
	timeProvider := &DefaultTimeProvider{}
	timeout := timeProvider.IntToDuration(ttl)
	if h.IsProduction() {
		data, err := h.Encrypt(data, nil)
		if err != nil {
			log.Println(err)
			return err
		}
		return redisClient.Set(key, data, timeout)
	}
	return redisClient.Set(key, string(data), timeout)
}
func (h *Helpers) GetCache(key string) (*string, error) {
	data, err := redisClient.Get(key)
	if err != nil {
		return nil, err
	}

	if h.IsProduction() {
		decryptedData, err := h.Decrypt(data, nil)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		data = string(decryptedData)
	}
	return &data, nil
}
func (h *Helpers) DeleteCache(key string) error {
	return redisClient.Clear(key)
}
func (h *Helpers) LoadConfig(conf any) error {
	if conf == nil {
		return fmt.Errorf("config parameter must not be nil")
	}

	rv := reflect.ValueOf(conf)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("config must be a non-nil pointer")
	}

	projectRoot, err := h.FindProjectRoot()
	if err != nil {
		return fmt.Errorf("project root not found: %w", err)
	}
	// Validate and build config path
	fileConfig := os.Getenv("FILE_CONFIG")
	if fileConfig == "" {
		return fmt.Errorf("missing FILE_CONFIG environment variable")
	}

	fullPath := filepath.Join(projectRoot, "config", fileConfig)
	// Decode TOML file
	if _, err := toml.DecodeFile(fullPath, conf); err != nil {
		return err
	}

	return nil
}
func (h *Helpers) FindProjectRoot() (string, error) {
	// Start from current working directory
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Traverse upwards until we find go.mod
	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			// Fallback: just use current working directory
			return wd, nil
		}
		current = parent
	}
}
func (h *Helpers) GetDefaultLimitData() int {
	var (
		limit  int
		config types.MainConfig
	)
	_ = h.LoadConfig(&config)
	limit = constants.DEFAULT_LIMIT_DATA

	return limit
}
func (h *Helpers) ErrorFatal(err error) {
	if err != nil {
		panic(err)
	}
}
func (h *Helpers) ErrorResponse(context *gin.Context, code int, message string) {
	if code == constants.WrongCredential {
		code = constants.Unauthorized
	}
	resp := types.ResponseDefault{
		Status:  false,
		Code:    code,
		Data:    nil,
		Message: message,
	}
	h.SendResponse(context, resp)
	context.Abort()
}
func (h *Helpers) ErrorMessage(code int) string {
	errorMessages := map[int]string{
		constants.BadRequest:          "Bad Request",
		constants.Unauthorized:        "Unauthorized",
		constants.Forbidden:           "Forbidden",
		constants.NotFound:            "Not Found",
		constants.MethodNotAllowed:    "Method Not Allowed",
		constants.InternalServerError: "Internal Server Error",
		constants.ServiceUnavailable:  "Service Unavailable",
		constants.GatewayTimeout:      "Gateway Timeout",
		constants.ServiceBroken:       "Service Not Completed",
		constants.WrongCredential:     "Username or Password is incorrect",
	}
	return errorMessages[code]
}
func (h *Helpers) GetStringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}
func (h *Helpers) GetBoolValue(ptr *bool) string {
	if ptr == nil {
		return ""
	}
	return fmt.Sprintf("%t", *ptr)
}
func (h *Helpers) JSONToStruct(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
func (h *Helpers) StructToJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
func (h *Helpers) InterfaceToStruct(data any, v interface{}) error {
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}
	temp, err := h.StructToJSON(data)
	if err != nil {
		return err
	}

	return h.JSONToStruct(temp, v)
}
func (h *Helpers) SendResponse(ctx *gin.Context, response types.ResponseDefault) {
	ctx.JSON(response.Code, response)
}
func (h *Helpers) GenerateRandomLabel(prefix string, n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return prefix + string(b)
}
func (h *Helpers) FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KBytes", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d Bytes", bytes)
	}
}
func (h *Helpers) Encrypt(plaintext []byte, key *string) (string, error) {
	if key == nil {
		keyConfig := h.GetMainConfig().App.AppKey
		key = &keyConfig
	}
	keyBytes := []byte(*key)

	// generate iv 16 bytes
	ivBytes := make([]byte, 16)
	_, err := rand.Read(ivBytes)
	if err != nil {
		log.Printf("Error generating random IV: %v\n", err)
		return "", err
	}

	// Ensure the key is 32 bytes for AES-256
	if len(keyBytes) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Printf("Error creating cipher: %v\n", err)
		return "", err
	}

	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	paddedText := append(plaintext, make([]byte, padding)...)

	mode := cipher.NewCBCEncrypter(block, ivBytes)

	// Encrypt the data
	ciphertext := make([]byte, len(paddedText))
	mode.CryptBlocks(ciphertext, paddedText)

	base64Ciphertext := base64.StdEncoding.EncodeToString(ciphertext)

	ivCiphertext := append(ivBytes, []byte(base64Ciphertext)...)
	return base64.StdEncoding.EncodeToString(ivCiphertext), nil
}
func (h *Helpers) Decrypt(ciphertextBase64 string, key *string) ([]byte, error) {
	if key == nil {
		keyConfig := h.GetMainConfig().App.AppKey
		key = &keyConfig
	}

	if len(*key) != 32 {
		err := errors.New("APP_KEY must be 32 bytes long for AES-256")
		return nil, err
	}
	// Create a new AES cipher
	block, err := aes.NewCipher([]byte(*key))
	if err != nil {
		log.Printf("Error creating cipher: %v\n", err)
		return nil, err
	}

	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		log.Printf("Error decoding ciphertext: %v\n", err)
		return nil, err
	}

	// Check if the ciphertext is valid
	if len(ciphertext) < aes.BlockSize {
		log.Println("ciphertext too short")
		return nil, errors.New("ciphertext too short")
	}

	// Get the IV (Initialization Vector)
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// decrypt base64 from ciphertext
	ciphertext, err = base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		log.Printf("Error base64 decoding ciphertext: %v\n", err)
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		message := "ciphertext is not a multiple of block size"
		log.Println(message)
		return nil, errors.New(message)
	}

	// Decrypt the ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove PKCS#7 padding
	return h.ZeroUnpad(h.Unpad(ciphertext)), nil
}
func (h *Helpers) Unpad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil
	}
	return src[:(length - unpadding)]
}
func (h *Helpers) ZeroUnpad(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}
func (h *Helpers) GetMainConfig() types.MainConfig {
	config := types.MainConfig{}
	_ = h.LoadConfig(&config)
	return config
}
func (h *Helpers) SetTokenActive(token string) {
	tokenActive = token
}
func (h *Helpers) GetTokenActive() string {
	return tokenActive
}
func (h *Helpers) SetUserActive(user models.User) {
	userActive = user
}
func (h *Helpers) GetUserActive() models.User {
	return userActive
}
func (h *Helpers) SetUserToken(token string) {
	tokenUser = token
}
func (h *Helpers) GetUserToken() string {
	return tokenUser
}
func (h *Helpers) IsFileComplete(filePath string) bool {
	// Check if file is being written to by trying to open it exclusively
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer file.Close()

	// Check if file has content and ends properly
	stat, err := file.Stat()
	if err != nil || stat.Size() == 0 {
		return false
	}

	// For JSON files, do a quick validation by reading last few bytes
	if stat.Size() > 2 {
		// Seek to near the end
		file.Seek(-2, 2)
		buffer := make([]byte, 2)
		n, err := file.Read(buffer)
		if err != nil || n != 2 {
			return false
		}

		// Check if file ends with valid JSON (should end with '}' or similar)
		lastChar := buffer[n-1]
		return lastChar == '}' || lastChar == ']'
	}

	return true
}
func (h *Helpers) ReadJSONFile(filePath string, target interface{}) error {
	// Wait a bit to ensure file write is complete
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if h.IsFileComplete(filePath) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Verify it's valid JSON before unmarshaling
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON in file: %s", filePath)
	}

	return json.Unmarshal(data, target)
}
func (h *Helpers) HashPassword(password string) (string, error) {
	const cost = 12
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(hashed), err
}
func (h *Helpers) VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Printf("Password verification failed: %v\n", err)
		return false
	}
	return true
}
func (h *Helpers) GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := cryptorand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
func (h *Helpers) LoadTimeLocale(locale string) *time.Location {
	// Load the timezone location
	location, err := time.LoadLocation(locale)
	if err != nil {
		// Fallback to UTC if timezone is invalid
		location = time.UTC
	}

	return location
}
func (h *Helpers) NormalizePhone(phonestring string) string {
	// Remove all spaces and trim
	phone := strings.ReplaceAll(strings.TrimSpace(phonestring), " ", "")

	// If phone is empty, return empty string
	if phone == "" {
		return ""
	}

	// List of common country codes to normalize
	countryCodes := []string{
		"+62", "62", // Indonesia
		"+61", "61", // Australia
		"+1", "1", // USA/Canada
		"+44", "44", // UK
		"+81", "81", // Japan
		"+86", "86", // China
		"+91", "91", // India
		"+33", "33", // France
		"+49", "49", // Germany
		"+39", "39", // Italy
		"+34", "34", // Spain
		"+7", "7", // Russia
		"+82", "82", // South Korea
		"+65", "65", // Singapore
		"+60", "60", // Malaysia
		"+66", "66", // Thailand
		"+84", "84", // Vietnam
		"+63", "63", // Philippines
		"+852", "852", // Hong Kong
		"+886", "886", // Taiwan
	}

	// Check if phone starts with any country code and replace with "0"
	for _, code := range countryCodes {
		if strings.HasPrefix(phone, code) {
			return "0" + phone[len(code):]
		}
	}

	// If no country code found, return as is
	return phone
}
func (h *Helpers) DefaultValue(ptr *string, defaultValue string) string {
	if ptr == nil || *ptr == "" {
		return defaultValue
	}
	return *ptr
}
func (h *Helpers) GetTimeProvider() TimeProvider {
	return h.TimeHelper
}

func (h *Helpers) GenerateJWTToken(payLoad any, expires time.Time) (string, error) {
	key := h.GetMainConfig().App.AppKey

	payloadJSON, err := h.StructToJSON(payLoad)
	if err != nil {
		return "", fmt.Errorf("failed to convert payload to JSON: %w", err)
	}
	payloadEncrypt, err := h.Encrypt(payloadJSON, &key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt payload: %w. %s", err, key)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"data": payloadEncrypt,
		"exp":  expires.Unix(),
	})
	signedToken, err := token.SignedString([]byte(key))

	return signedToken, err
}

func (h *Helpers) ParsingJWT(token string, payload interface{}) error {
	key := h.GetMainConfig().App.AppKey
	tokenjwt, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signin method")
		}
		return []byte(key), nil
	})
	if err != nil || !tokenjwt.Valid {
		return fmt.Errorf("unauthorized User")
	}

	claims := tokenjwt.Claims.(jwt.MapClaims)
	payloadEncrypt := claims["data"]
	payloadDecrypt, err := h.Decrypt(payloadEncrypt.(string), &key)
	if err != nil {
		return err
	}
	err = h.JSONToStruct(payloadDecrypt, &payload)

	return err
}
func (h *Helpers) SendResponseData(ctx *gin.Context, code int, message string, data any) {
	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    data,
		Message: message,
	}
	h.SendResponse(ctx, response)
}

// FormatValidationError converts validator errors to user-friendly messages
func (h *Helpers) FormatValidationError(err error) string {
	if err == nil {
		return ""
	}

	// Check if it's a validator.ValidationErrors type
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		// Get the first error
		if len(validationErrs) > 0 {
			firstErr := validationErrs[0]
			fieldName := firstErr.Field()
			tag := firstErr.Tag()
			param := firstErr.Param()

			// Convert field name to lowercase for better readability
			friendlyFieldName := h.toFriendlyFieldName(fieldName)

			// Generate dynamic error messages based on validation tag
			switch tag {
			case "required":
				return fmt.Sprintf("%s is required", friendlyFieldName)
			case "email":
				return fmt.Sprintf("%s must be a valid email address", friendlyFieldName)
			case "min":
				return fmt.Sprintf("%s must be at least %s characters", friendlyFieldName, param)
			case "max":
				return fmt.Sprintf("%s must not exceed %s characters", friendlyFieldName, param)
			case "eqfield":
				// Get the field it should equal to
				paramFieldName := h.toFriendlyFieldName(param)
				return fmt.Sprintf("%s must match %s", friendlyFieldName, paramFieldName)
			case "required_without":
				paramFieldName := h.toFriendlyFieldName(param)
				return fmt.Sprintf("Either %s or %s is required", friendlyFieldName, paramFieldName)
			case "oneof":
				return fmt.Sprintf("%s must be one of: %s", friendlyFieldName, param)
			case "gt":
				return fmt.Sprintf("%s must be greater than %s", friendlyFieldName, param)
			case "gte":
				return fmt.Sprintf("%s must be greater than or equal to %s", friendlyFieldName, param)
			case "lt":
				return fmt.Sprintf("%s must be less than %s", friendlyFieldName, param)
			case "lte":
				return fmt.Sprintf("%s must be less than or equal to %s", friendlyFieldName, param)
			default:
				return fmt.Sprintf("%s is invalid", friendlyFieldName)
			}
		}
	}

	// If not a validation error, return generic message
	return "Invalid input data"
}

// toFriendlyFieldName converts CamelCase field names to friendly format
// Example: "ConfirmPassword" -> "confirm password"
func (h *Helpers) toFriendlyFieldName(fieldName string) string {
	if fieldName == "" {
		return ""
	}

	// Insert space before uppercase letters
	var result strings.Builder
	for i, char := range fieldName {
		if i > 0 && char >= 'A' && char <= 'Z' {
			result.WriteRune(' ')
		}
		result.WriteRune(char)
	}

	return strings.ToLower(result.String())
}

func (h *Helpers) SetupLogging() {
	if h.IsProduction() {
		// Create logs directory if it doesn't exist
		logsDir := "logs"
		if err := os.MkdirAll(logsDir, 0755); err != nil {
			log.Fatalf("Failed to create logs directory: %v", err)
		}

		// Generate daily log filename with format: app-YYYY-MM-DD.log
		logFileName := filepath.Join(logsDir, "app-"+time.Now().Format(constants.FORMAT_DATE)+".log")

		// Open or create log file
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}

		// Set log output to file
		log.SetOutput(logFile)
		log.Printf("Logging initialized in RELEASE mode - writing to file: %s", logFileName)
	} else {
		// Development mode: log to stdout (visible in podman logs)
		log.SetOutput(os.Stdout)
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("Logging initialized in DEVELOPMENT mode - writing to stdout")
	}
}

func (h *Helpers) ContainString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

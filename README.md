# Go Microservice Boilerplate

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/golang-boilerplate)](https://goreportcard.com/report/github.com/yourusername/golang-boilerplate)
[![Maintainability](https://img.shields.io/badge/maintainability-A-green)](https://codeclimate.com)

> A production-ready Go microservice boilerplate with clean architecture, built-in authentication, database seeding, and comprehensive testing.

## ✨ Features

- 🏗️ **Clean Architecture** - Organized codebase with clear separation of concerns
- 🔐 **Authentication System** - JWT-based auth with refresh tokens
- 🗄️ **Multi-Database Support** - PostgreSQL, MySQL, SQLite
- 📊 **Database Seeding** - Laravel-style seeders with console commands
- 🧪 **100% Test Coverage** - Comprehensive unit tests with mocking
- 📝 **API Documentation** - Swagger/OpenAPI integration
- 🔄 **Message Brokers** - RabbitMQ and Kafka support
- 📦 **Object Storage** - S3/MinIO integration
- 🚀 **Hot Reload** - Development with live reloading
- 🐳 **Docker Ready** - Development and production Dockerfiles
- 🎯 **Console Commands** - Laravel Artisan-like CLI for common tasks
- 📡 **Redis Caching** - Built-in cache layer

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Database](#-database)
- [Console Commands](#-console-commands)
- [Testing](#-testing)
- [API Documentation](#-api-documentation)
- [Development](#-development)
- [Deployment](#-deployment)
- [Contributing](#-contributing)

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/golang-boilerplate.git
cd golang-boilerplate

# Install dependencies
go mod download

# Copy configuration
cp config/example.toml config/app.toml

# Run database migrations
go run main.go migrate

# Seed the database
go run main.go seed

# Start the server
go run main.go
```

The server will start on `http://localhost:5000`

## 📁 Project Structure

```
golang-boilerplate/
├── config/                 # Configuration files
│   └── config.toml        # Main configuration
├── database/              # Database layer
│   ├── seeder.go         # Seeder registry
│   └── seeders/          # Database seeders
│       ├── database_seeder.go
│       ├── role_seeder.go
│       └── user_seeder.go
├── docs/                  # API documentation (Swagger)
├── src/                   # Source code
│   ├── connections/       # Database & external connections
│   │   ├── database.go
│   │   ├── redis.go
│   │   ├── rabbitmq.go
│   │   ├── kafka.go
│   │   └── s3client.go
│   ├── console/           # Console commands
│   │   ├── kernel.go
│   │   ├── register.go
│   │   └── commands/
│   │       └── seed_command.go
│   ├── constants/         # Application constants
│   ├── controllers/       # HTTP handlers
│   ├── helpers/           # Helper functions
│   ├── middlewares/       # HTTP middlewares
│   ├── models/            # Data models (GORM)
│   │   ├── user.go
│   │   ├── role.go
│   │   ├── user_session.go
│   │   └── user_profile.go
│   ├── repositories/      # Data access layer
│   │   ├── UserRepository.go
│   │   ├── RoleRepository.go
│   │   └── ...
│   ├── router/            # Route definitions
│   ├── services/          # Business logic
│   │   └── authorizations.go
│   └── types/             # Type definitions
│       ├── auth.go
│       ├── request.go
│       └── default.go
├── tests/                 # Test files
│   ├── mocks/             # Mock implementations
│   │   ├── mock_helper.go
│   │   └── mock_repositories.go
│   └── services/          # Service tests
│       ├── authorization_service_test.go
│       ├── authorization_refresh_token_test.go
│       ├── authorization_register_test.go
│       └── authorization_verify_test.go
├── dev.Dockerfile         # Development Dockerfile
├── prod.Dockerfile        # Production Dockerfile
├── go.mod                 # Go modules
├── go.sum                 # Dependencies checksums
└── main.go                # Application entry point
```

## 💻 Installation

### Prerequisites

- Go 1.21 or higher
- PostgreSQL/MySQL/SQLite (choose one)
- Redis (optional)
- RabbitMQ or Kafka (optional)
- Docker & Podman (optional)

### Local Installation

```bash
# Install Go dependencies
go mod download
go mod tidy

# Install testing dependencies
go get github.com/stretchr/testify/suite
go get github.com/stretchr/testify/mock
```

### Docker Installation

```bash
# Build Docker image
docker build -f dev.Dockerfile --build-arg PLATFORM=linux/amd64 --build-arg PORT=5000 -t go-boilerplate:dev .
# Build Docker Image Production
docker build -f prod.Dockerfile --build-arg PLATFORM=linux/amd64 --build-arg PORT=5000  --build-arg TZ=Asia/Jakarta -t go-boilerplate:prod .

# Run container
docker run -p 5000:5000 -v $(pwd):/go/src/app -e FILE_CONFIG=app.toml go-boilerplate:dev
# Run container production
docker run -p 5000:5000 -e FILE_CONFIG=app.toml go-boilerplate:prod
```

### Podman Installation

```bash
# Build with Podman
podman build -f dev.Dockerfile --build-arg PLATFORM=linux/amd64 --build-arg PORT=5000 -t go-boilerplate:dev .
# Build with Podman Production
podman build -f prod.Dockerfile --build-arg PLATFORM=linux/amd64 --build-arg PORT=5000  --build-arg TZ=Asia/Jakarta -t go-boilerplate:prod .

# Run container
podman run -it --rm -p 5000:5000 -v $(pwd):/go/src/app -e FILE_CONFIG=app.toml go-boilerplate:dev
podman run -p 5000:5000 -e FILE_CONFIG=app.toml go-boilerplate:prod
```

## ⚙️ Configuration

Configuration is managed through TOML files in the `config/` directory.

### Setup Configuration

```bash
# Copy example configuration
cp config/example.toml config/app.toml

# Edit the configuration
nano config/app.toml
```

### Configuration Format

```toml
# Database Configuration
[database]
type = "postgres"       # Options: "postgres", "mysql", "sqlite"
host = "localhost"
port = 5432
user = "postgres"
password = "postgres"
db_name = "myapp_db"

# Redis Configuration
[redis]
host = "localhost"
port = 6379
password = ""           # Leave empty if no password
db = 0                  # Default database
db_pub_sub = 1         # Database for pub/sub operations

# Message Broker Configuration
[message_broker]
provider = "rabbitmq"   # Options: "kafka" or "rabbitmq"

# RabbitMQ Configuration
[rabbitmq]
host = "localhost"
port = 5672
username = "guest"
password = "guest"
vhost = "/"

# Kafka Configuration
[kafka]
address = "localhost:9092"
username = ""
password = ""

# S3 Storage Configuration
[s3]
provider = "minio"              # Options: "aws" or "minio"
endpoint = "http://localhost:9000"
region = "us-east-1"
access_key_id = "minioadmin"
secret_access_key = "minioadmin"
use_ssl = false
bucket_name = "my-bucket"

# CORS Configuration
[cors]
allowed_url = "*"       # Use "*" for all origins or comma-separated URLs

# SFTP Configuration (optional)
[sftp]
host = "localhost"
port = 22
user = "sftp_user"
password = "sftp_password"

# Bulk Data Configuration
[bulk]
limit_data = 1000
```

### Environment Variables

```bash
# Server
PORT=5000
HOST=localhost
GIN_MODE=debug  # or "release" for production
FILE_CONFIG=app.toml # your config filename
```

## 🗄️ Database

### Supported Databases

- PostgreSQL
- MySQL
- SQLite

### Migrations

```bash
# Auto-migrate (creates/updates tables)
go run main.go migrate

# The migrations are handled by GORM AutoMigrate
```

### Database Seeding

The project includes Laravel-style database seeders:

```bash
# Run all seeders
go run main.go seed

# Run specific seeder
go run main.go seed --class RoleSeeder
go run main.go seed --class UserSeeder

# List available seeders
go run main.go seed --list

# Show seeder help
go run main.go seed --help
```
when in production already build change `go run main.go` to your binary build name, example if build name is `app` the command is 

```bash
app --help
app --list
app seed
```

#### Available Seeders

| Seeder | Description |
|--------|-------------|
| **RoleSeeder** | Seeds default roles (admin, user, moderator) |

#### Default Seed Data

After running seeders, you'll have:
**Roles:**
- Admin - Full permissions
- User - Basic permissions
- Moderator - Content management permissions

### Creating Custom Seeders

1. Create a new file in `database/seeders/`:

```go
package seeders

import (
    "app/src/models"
    "gorm.io/gorm"
)

type ProductSeeder struct{}

func (s *ProductSeeder) GetName() string {
    return "ProductSeeder"
}

func (s *ProductSeeder) Seed(db *gorm.DB) error {
    products := []models.Product{
        {Name: "Product 1", Price: 100},
        {Name: "Product 2", Price: 200},
    }

    for _, product := range products {
        var existing models.Product
        if err := db.Where("name = ?", product.Name).First(&existing).Error; err != nil {
            if err == gorm.ErrRecordNotFound {
                if err := db.Create(&product).Error; err != nil {
                    return err
                }
            }
        }
    }
    return nil
}
```

2. Register in `database/seeders/database_seeder.go`:

```go
func NewDatabaseSeeder() *DatabaseSeeder {
    registry := database.NewSeederRegistry()
    registry.Register(&RoleSeeder{})
    registry.Register(&UserSeeder{})
    registry.Register(&ProductSeeder{})  // Add here
    return &DatabaseSeeder{registry: registry}
}
```

## 🎯 Console Commands

The application includes an Artisan-style console command system:

```bash
# Show all available commands
go run main.go --help

# List all commands
go run main.go --list

# Database seeding
go run main.go seed
go run main.go seed --class RoleSeeder
go run main.go seed --list
```

### Creating Custom Commands

1. Create command file in `src/console/commands/`:

```go
package commands

import (
    "app/src/helpers"
    "fmt"
)

type YourCommand struct{}

func (c *YourCommand) Name() string {
    return "your-command"
}

func (c *YourCommand) Description() string {
    return "Description of your command"
}

func (c *YourCommand) Execute(h helpers.HelperInterface, args []string) error {
    fmt.Println("Executing your command...")
    // Your logic here
    return nil
}
```

2. Register in `src/console/register.go`:

```go
func RegisterCommands(h helpers.HelperInterface) *Kernel {
    kernel := NewKernel(h)
    kernel.Register(&commands.SeedCommand{})
    kernel.Register(&commands.YourCommand{})  // Add here
    return kernel
}
```

## 🧪 Testing

The project includes comprehensive unit tests with 100% mocking.

### Running Tests

```bash
# Run all tests
go test ./tests/services/... -v

# Run with coverage
go test ./tests/services/... -cover

# Generate coverage report
go test ./tests/services/... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific tests
go test ./tests/services/... -run TestAuthorize -v
go test ./tests/services/... -run Success -v      # Only success cases
go test ./tests/services/... -run Failure -v      # Only failure cases

# Run with race detection
go test ./tests/services/... -race -v

# Run in parallel
go test ./tests/services/... -parallel 4 -v
```

### Test Coverage

| Service | Functions | Tests | Coverage |
|---------|-----------|-------|----------|
| **AuthorizationsService** | 7 | 35 | 100% |

All tests use mocking - no real database required!

### Test Structure

```
tests/
├── mocks/                          # Mock implementations
│   ├── mock_helper.go             # Helper mock
│   └── mock_repositories.go       # Repository mocks
└── services/                       # Service tests
    ├── authorization_service_test.go        # Authorize tests
    ├── authorization_refresh_token_test.go  # RefreshToken tests
    ├── authorization_register_test.go       # RegisterUser tests
    └── authorization_verify_test.go         # Verify/Revoke/List tests
```

For more details, see [tests/README.md](tests/README.md)

## 📚 API Documentation

API documentation is available via Swagger/OpenAPI.

### Accessing Documentation

```bash
# Start the server
go run main.go

# Open in browser
http://localhost:5000/documentation/index.html
```

### Generating Documentation

```bash
# Install swag
go install github.com/swaggo/swag/cmd/swag@latest

# Generate docs
swag init

# Docs will be in docs/ directory
```

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/login` | User login |
| GET | `/v1/refresh` | Refresh access token |
| POST | `/v1/register` | User registration |
| GET | `/v1/user/roles` | List user roles |
| POST | `/v1/logout` | Logout user |

## 🛠️ Development

### Development with Hot Reload

```bash
# Using gin (recommended)
gin -i -a 500

# Using air
air
```

### Code Quality

```bash
# Format code
go fmt ./...

# Run linter
golangci-lint run

# Check for issues
go vet ./...
```

### Adding New Features

1. **Add Model** in `src/models/`
2. **Add Repository** in `src/repositories/`
3. **Add Service** in `src/services/`
4. **Add Controller** in `src/controllers/`
5. **Add Routes** in `src/router/`
6. **Add Tests** in `tests/`

## 🚀 Deployment

### Building for Production

```bash
# Build binary
go build -o app main.go

# Run binary
./app
```

### Docker Production Build

```bash
# Build production image
docker build -f prod.Dockerfile -t go-boilerplate:prod .

# Run production container
docker run -p 5000:5000 --env-file .env go-boilerplate:prod
```

### Environment Variables for Production

```bash
GIN_MODE=release
PORT=5000
FILE_CONFIG=app.toml
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards

- Follow Go best practices
- Write unit tests for new features
- Update documentation
- Run `go fmt` before committing
- Ensure all tests pass

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Your Name**
- Email: arfan.zarkasi@gmail.com
- GitHub: [@yourusername](https://github.com/yourusername)

## 🙏 Acknowledgments

- [Gin Framework](https://github.com/gin-gonic/gin)
- [GORM](https://gorm.io/)
- [Testify](https://github.com/stretchr/testify)
- [Swagger](https://swagger.io/)

## 📊 Stats

![GitHub stars](https://img.shields.io/github/stars/yourusername/golang-boilerplate?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/golang-boilerplate?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/golang-boilerplate)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/golang-boilerplate)

---

⭐️ If you find this project useful, please consider giving it a star!

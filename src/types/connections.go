package types

type DBType string

const (
	DBTypePostgres DBType = "postgres"
	DBTypeMySQL    DBType = "mysql"
	DBTypeSQLite   DBType = "sqlite"
)

type BrokerType string

const (
	BrokerTypeKafka    BrokerType = "kafka"
	BrokerTypeRabbitMQ BrokerType = "rabbitmq"
)

type S3Provider string

const (
	S3ProviderAWS   S3Provider = "aws"
	S3ProviderMinio S3Provider = "minio"
)

type MainConfig struct {
	Sftp struct {
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	} `toml:"sftp"`
	BulkData struct {
		LimitData int `toml:"limit_data"`
	} `toml:"bulk"`
	MessageBroker struct {
		Provider BrokerType `toml:"provider"`
	} `toml:"message_broker"`
	Kafka struct {
		Address  string `toml:"address"`
		Username string `toml:"username"`
		Password string `toml:"password"`
	} `toml:"kafka"`
	RabbitMQ struct {
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
		Username string `toml:"username"`
		Password string `toml:"password"`
		VHost    string `toml:"vhost"`
	} `toml:"rabbitmq"`
	Redis struct {
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
		Password string `toml:"password"`
		DB       int    `toml:"db"`
		DBPubSub int    `toml:"db_pub_sub"`
	} `toml:"redis"`
	Cors struct {
		AllowedUrl string `toml:"allowed_url"`
	} `toml:"cors"`
	Database struct {
		Type     DBType `toml:"type"`
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
		User     string `toml:"user"`
		Password string `toml:"password"`
		DBName   string `toml:"db_name"`
	} `toml:"database"`
	S3 struct {
		Provider        S3Provider `toml:"provider"`
		Endpoint        string     `toml:"endpoint"`
		Region          string     `toml:"region"`
		AccessKeyID     string     `toml:"access_key_id"`
		SecretAccessKey string     `toml:"secret_access_key"`
		UseSSL          bool       `toml:"use_ssl"`
		BucketName      string     `toml:"bucket_name"`
	} `toml:"s3"`
	App struct {
		AppKey string `toml:"app_key"` // 32 byte secure random string
	} `toml:"app"`
}

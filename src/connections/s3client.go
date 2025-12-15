package connections

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"app/src/constants"
	apptypes "app/src/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Client interface {
	Client() *s3.Client
	UploadFile(ctx context.Context, key string, data []byte, contentType string) error
	DownloadFile(ctx context.Context, key string) ([]byte, error)
	DeleteFile(ctx context.Context, key string) error
	ListFiles(ctx context.Context, prefix string) ([]string, error)
	FileExists(ctx context.Context, key string) (bool, error)
	GetFileURL(key string, expiration time.Duration) (string, error)
	GetFileExtension(key string) string
	IsConnected() bool
	Close() error
	IsLocalStorage() bool
}

type s3Wrapper struct {
	client   *s3.Client
	config   apptypes.MainConfig
	bucket   string
	provider apptypes.S3Provider
}

func NewS3Client(cfg apptypes.MainConfig) (S3Client, error) {
	var awsConfig aws.Config
	var err error

	ctx := context.Background()

	switch cfg.S3.Provider {
	case apptypes.S3ProviderLocal:
		// Local file storage configuration
		uploadPath := constants.DEFAULT_PATH_UPLOAD
		if err := os.MkdirAll(uploadPath, constants.DEFAULT_PERMISSION); err != nil {
			return nil, fmt.Errorf("failed to create upload directory: %w", err)
		}

		log.Printf("Successfully initialized local file storage at: %s", uploadPath)

		return &s3Wrapper{
			client:   nil, // No S3 client needed for local storage
			config:   cfg,
			bucket:   cfg.S3.BucketName,
			provider: apptypes.S3ProviderLocal,
		}, nil

	case apptypes.S3ProviderAWS:
		// AWS S3 configuration
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.S3.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.S3.AccessKeyID,
				cfg.S3.SecretAccessKey,
				"",
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

	case apptypes.S3ProviderMinio:
		// Minio configuration (S3-compatible)
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.S3.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.S3.AccessKeyID,
				cfg.S3.SecretAccessKey,
				"",
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load Minio config: %w", err)
		}

	default:
		// Default to custom endpoint (supports any S3-compatible storage)
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.S3.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.S3.AccessKeyID,
				cfg.S3.SecretAccessKey,
				"",
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load S3 config: %w", err)
		}
	}

	// Create S3 client with custom endpoint resolver for Minio or custom S3
	var client *s3.Client
	if cfg.S3.Endpoint != "" {
		client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3.Endpoint)
			o.UsePathStyle = true // Required for Minio
		})
	} else {
		client = s3.NewFromConfig(awsConfig)
	}

	// Test connection by listing buckets
	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to S3: %w", err)
	}

	log.Printf("Successfully connected to S3 provider: %s", cfg.S3.Provider)

	return &s3Wrapper{
		client:   client,
		config:   cfg,
		bucket:   cfg.S3.BucketName,
		provider: cfg.S3.Provider,
	}, nil
}

func (s *s3Wrapper) Client() *s3.Client {
	return s.client
}

func (s *s3Wrapper) UploadFile(ctx context.Context, key string, data []byte, contentType string) error {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		filePath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, key)

		// Create directory if it doesn't exist
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, constants.DEFAULT_PERMISSION); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Write file to local storage
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file to local storage: %w", err)
		}

		log.Printf("File uploaded successfully to local storage: path=%s size=%d", filePath, len(data))
		return nil
	}

	// S3 upload
	bucket := s.bucket

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	}

	_, err := s.client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	log.Printf("File uploaded successfully: bucket=%s key=%s size=%d", bucket, key, len(data))
	return nil
}

func (s *s3Wrapper) DownloadFile(ctx context.Context, key string) ([]byte, error) {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		filePath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, key)

		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file from local storage: %w", err)
		}

		log.Printf("File downloaded successfully from local storage: path=%s size=%d", filePath, len(data))
		return data, nil
	}

	// S3 download
	bucket := s.bucket

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to download file from S3: %w", err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	log.Printf("File downloaded successfully: bucket=%s key=%s size=%d", bucket, key, len(data))
	return data, nil
}

func (s *s3Wrapper) DeleteFile(ctx context.Context, key string) error {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		filePath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, key)

		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to delete file from local storage: %w", err)
		}

		log.Printf("File deleted successfully from local storage: path=%s", filePath)
		return nil
	}

	// S3 delete
	bucket := s.bucket

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := s.client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete file from S3: %w", err)
	}

	log.Printf("File deleted successfully: bucket=%s key=%s", bucket, key)
	return nil
}

func (s *s3Wrapper) ListFiles(ctx context.Context, prefix string) ([]string, error) {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		searchPath := constants.DEFAULT_PATH_UPLOAD
		if prefix != "" {
			searchPath = filepath.Join(constants.DEFAULT_PATH_UPLOAD, prefix)
		}

		var keys []string
		err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				relPath, err := filepath.Rel(constants.DEFAULT_PATH_UPLOAD, path)
				if err != nil {
					return err
				}
				keys = append(keys, filepath.ToSlash(relPath))
			}
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed to list files from local storage: %w", err)
		}

		log.Printf("Listed %d files from local storage: prefix=%s", len(keys), prefix)
		return keys, nil
	}

	// S3 list
	bucket := s.bucket

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}

	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}

	result, err := s.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list files from S3: %w", err)
	}

	var keys []string
	for _, obj := range result.Contents {
		if obj.Key != nil {
			keys = append(keys, *obj.Key)
		}
	}

	log.Printf("Listed %d files from bucket=%s prefix=%s", len(keys), bucket, prefix)
	return keys, nil
}

func (s *s3Wrapper) FileExists(ctx context.Context, key string) (bool, error) {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		filePath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, key)

		_, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("failed to check file existence: %w", err)
		}

		return true, nil
	}

	// S3 check
	bucket := s.bucket

	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := s.client.HeadObject(ctx, input)
	if err != nil {
		// Check if error is NotFound (404)
		var nfe *types.NotFound
		if errors.As(err, &nfe) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check file existence: %w", err)
	}

	return true, nil
}

func (s *s3Wrapper) GetFileURL(key string, expiration time.Duration) (string, error) {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		host := os.Getenv("HOST")
		// For local storage, return a relative path that can be served by the application
		// The application should handle serving files from the uploads directory
		// fileURL := filepath.ToSlash(filepath.Join(constants.DEFAULT_PATH_UPLOAD, key))
		fullUrl := host + "/images?to=" + key
		log.Printf("Generated local file URL: path=%s", fullUrl)
		return fullUrl, nil
	}

	// S3 presigned URL
	bucket := s.bucket

	// Create presigned client
	presignClient := s3.NewPresignClient(s.client)

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := presignClient.PresignGetObject(context.Background(), input, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	log.Printf("Generated presigned URL for bucket=%s key=%s expires_in=%s", bucket, key, expiration)
	return result.URL, nil
}

func (s *s3Wrapper) CreateBucket(ctx context.Context, bucket string) error {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		// For local storage, creating a bucket means creating a subdirectory
		bucketPath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, bucket)
		if err := os.MkdirAll(bucketPath, constants.DEFAULT_PERMISSION); err != nil {
			return fmt.Errorf("failed to create bucket directory: %w", err)
		}

		log.Printf("Bucket directory created successfully: %s", bucketPath)
		return nil
	}

	// S3 create bucket
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}

	// For regions other than us-east-1, we need to specify location constraint
	if s.config.S3.Region != "" && s.config.S3.Region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(s.config.S3.Region),
		}
	}

	_, err := s.client.CreateBucket(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	log.Printf("Bucket created successfully: %s", bucket)
	return nil
}

func (s *s3Wrapper) DeleteBucket(ctx context.Context, bucket string) error {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		// For local storage, deleting a bucket means removing the subdirectory
		bucketPath := filepath.Join(constants.DEFAULT_PATH_UPLOAD, bucket)
		if err := os.RemoveAll(bucketPath); err != nil {
			return fmt.Errorf("failed to delete bucket directory: %w", err)
		}

		log.Printf("Bucket directory deleted successfully: %s", bucketPath)
		return nil
	}

	// S3 delete bucket
	input := &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	}

	_, err := s.client.DeleteBucket(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete bucket: %w", err)
	}

	log.Printf("Bucket deleted successfully: %s", bucket)
	return nil
}

func (s *s3Wrapper) IsConnected() bool {
	// Handle local file storage
	if s.provider == apptypes.S3ProviderLocal {
		// Check if upload directory exists and is accessible
		_, err := os.Stat(constants.DEFAULT_PATH_UPLOAD)
		return err == nil
	}

	// S3 connection check
	if s.client == nil {
		return false
	}

	// Quick health check by listing buckets
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

func (s *s3Wrapper) Close() error {
	// AWS SDK v2 doesn't require explicit closing
	// But we can nil out the client
	s.client = nil
	log.Println("S3 client closed")
	return nil
}

func (s *s3Wrapper) GetFileExtension(key string) string {
	// Handle local file storage
	if s.IsLocalStorage() {
		path := filepath.Join(constants.DEFAULT_PATH_UPLOAD, key)
		return filepath.Ext(path)
	}

	// S3 file extension
	return filepath.Ext(key)
}

func (s *s3Wrapper) IsLocalStorage() bool {
	return s.provider == apptypes.S3ProviderLocal
}

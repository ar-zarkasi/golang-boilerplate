package connections

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	apptypes "app/src/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Client interface {
	Client() *s3.Client
	UploadFile(ctx context.Context, bucket, key string, data []byte, contentType string) error
	DownloadFile(ctx context.Context, bucket, key string) ([]byte, error)
	DeleteFile(ctx context.Context, bucket, key string) error
	ListFiles(ctx context.Context, bucket, prefix string) ([]string, error)
	FileExists(ctx context.Context, bucket, key string) (bool, error)
	GetFileURL(bucket, key string, expiration time.Duration) (string, error)
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error
	IsConnected() bool
	Close() error
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

func (s *s3Wrapper) UploadFile(ctx context.Context, bucket, key string, data []byte, contentType string) error {
	if bucket == "" {
		bucket = s.bucket
	}

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

func (s *s3Wrapper) DownloadFile(ctx context.Context, bucket, key string) ([]byte, error) {
	if bucket == "" {
		bucket = s.bucket
	}

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

func (s *s3Wrapper) DeleteFile(ctx context.Context, bucket, key string) error {
	if bucket == "" {
		bucket = s.bucket
	}

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

func (s *s3Wrapper) ListFiles(ctx context.Context, bucket, prefix string) ([]string, error) {
	if bucket == "" {
		bucket = s.bucket
	}

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

func (s *s3Wrapper) FileExists(ctx context.Context, bucket, key string) (bool, error) {
	if bucket == "" {
		bucket = s.bucket
	}

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

func (s *s3Wrapper) GetFileURL(bucket, key string, expiration time.Duration) (string, error) {
	if bucket == "" {
		bucket = s.bucket
	}

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

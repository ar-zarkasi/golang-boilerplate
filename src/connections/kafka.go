package connections

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"app/src/types"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
)

type Kafka interface {
	Connection() *kafka.Conn
	Writer(topic string) *kafka.Writer
	Reader(groupID string, topics []string) *kafka.Reader
	PublishMessage(ctx context.Context, topic string, key string, message []byte) error
	ConsumeMessages(ctx context.Context, groupID string, topics []string, handler func(kafka.Message) error) error
	CreateTopic(topic string, numPartitions int, replicationFactor int) error
	Close() error
	IsConnected() bool
}

type kafkaWrapper struct {
	brokers   []string
	config    types.MainConfig
	dialer    *kafka.Dialer
	conn      *kafka.Conn
	writers   map[string]*kafka.Writer
	readers   map[string]*kafka.Reader
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	connected bool
}

func NewKafka(cfg types.MainConfig) (Kafka, error) {
	brokers := strings.Split(cfg.Kafka.Address, ",")

	// Configure SASL if credentials are provided
	var mechanism plain.Mechanism
	var dialer *kafka.Dialer

	if cfg.Kafka.Username != "" && cfg.Kafka.Password != "" {
		mechanism = plain.Mechanism{
			Username: cfg.Kafka.Username,
			Password: cfg.Kafka.Password,
		}
		dialer = &kafka.Dialer{
			Timeout:       10 * time.Second,
			DualStack:     true,
			SASLMechanism: mechanism,
		}
	} else {
		dialer = &kafka.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		}
	}

	// Test connection
	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", brokers[0])
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kafka broker: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	wrapper := &kafkaWrapper{
		brokers:   brokers,
		config:    cfg,
		dialer:    dialer,
		conn:      conn,
		writers:   make(map[string]*kafka.Writer),
		readers:   make(map[string]*kafka.Reader),
		ctx:       ctx,
		cancel:    cancel,
		connected: true,
	}

	// Setup connection monitoring
	go wrapper.handleConnectionHealth()

	return wrapper, nil
}

func (k *kafkaWrapper) Connection() *kafka.Conn {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.conn
}

func (k *kafkaWrapper) Writer(topic string) *kafka.Writer {
	k.mu.Lock()
	defer k.mu.Unlock()

	if writer, exists := k.writers[topic]; exists {
		return writer
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(k.brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		MaxAttempts:  5,
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
		Compression:  kafka.Snappy,
		Transport:    &kafka.Transport{Dial: k.dialer.DialFunc},
	}

	k.writers[topic] = writer
	return writer
}

func (k *kafkaWrapper) Reader(groupID string, topics []string) *kafka.Reader {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := fmt.Sprintf("%s:%s", groupID, strings.Join(topics, ","))
	if reader, exists := k.readers[key]; exists {
		return reader
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        k.brokers,
		GroupID:        groupID,
		GroupTopics:    topics,
		MinBytes:       10e3, // 10KB
		MaxBytes:       10e6, // 10MB
		MaxWait:        500 * time.Millisecond,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
		Dialer:         k.dialer,
	})

	k.readers[key] = reader
	return reader
}

func (k *kafkaWrapper) PublishMessage(ctx context.Context, topic string, key string, message []byte) error {
	writer := k.Writer(topic)

	msg := kafka.Message{
		Key:   []byte(key),
		Value: message,
		Time:  time.Now(),
	}

	err := writer.WriteMessages(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to publish message to topic %s: %w", topic, err)
	}

	log.Printf("Message published to topic=%s key=%s", topic, key)
	return nil
}

func (k *kafkaWrapper) ConsumeMessages(ctx context.Context, groupID string, topics []string, handler func(kafka.Message) error) error {
	reader := k.Reader(groupID, topics)

	go func() {
		for {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				log.Println("Kafka consumer context cancelled, stopping consumption")
				return
			case <-k.ctx.Done():
				log.Println("Kafka wrapper context cancelled, stopping consumption")
				return
			default:
			}

			// Read message
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				if err == context.Canceled {
					log.Println("Kafka consumer context cancelled")
					return
				}
				log.Printf("Error fetching message: %v", err)
				time.Sleep(time.Second * 2)
				continue
			}

			log.Printf("Received message from topic=%s partition=%d offset=%d key=%s",
				msg.Topic, msg.Partition, msg.Offset, string(msg.Key))

			// Process message with handler
			if handler != nil {
				if err := handler(msg); err != nil {
					log.Printf("Error processing message: %v", err)
					continue
				}
			}

			// Commit message
			if err := reader.CommitMessages(ctx, msg); err != nil {
				log.Printf("Error committing message: %v", err)
			}
		}
	}()

	log.Printf("Started consuming messages from topics: %v with group: %s", topics, groupID)
	return nil
}

func (k *kafkaWrapper) CreateTopic(topic string, numPartitions int, replicationFactor int) error {
	k.mu.RLock()
	conn := k.conn
	k.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no active connection")
	}

	controller, err := conn.Controller()
	if err != nil {
		return fmt.Errorf("failed to get controller: %w", err)
	}

	controllerConn, err := k.dialer.Dial("tcp", fmt.Sprintf("%s:%d", controller.Host, controller.Port))
	if err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}
	defer controllerConn.Close()

	topicConfigs := []kafka.TopicConfig{
		{
			Topic:             topic,
			NumPartitions:     numPartitions,
			ReplicationFactor: replicationFactor,
		},
	}

	err = controllerConn.CreateTopics(topicConfigs...)
	if err != nil {
		return fmt.Errorf("failed to create topic: %w", err)
	}

	log.Printf("Topic created: %s with %d partitions", topic, numPartitions)
	return nil
}

func (k *kafkaWrapper) Close() error {
	k.cancel()

	k.mu.Lock()
	defer k.mu.Unlock()

	var errors []error

	// Close all writers
	for topic, writer := range k.writers {
		if err := writer.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close writer for topic %s: %w", topic, err))
		}
	}

	// Close all readers
	for key, reader := range k.readers {
		if err := reader.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close reader for %s: %w", key, err))
		}
	}

	// Close connection
	if k.conn != nil {
		if err := k.conn.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close connection: %w", err))
		}
	}

	k.connected = false

	if len(errors) > 0 {
		return fmt.Errorf("errors closing Kafka connections: %v", errors)
	}

	return nil
}

func (k *kafkaWrapper) IsConnected() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.connected && k.conn != nil
}

func (k *kafkaWrapper) handleConnectionHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-k.ctx.Done():
			return
		case <-ticker.C:
			k.mu.RLock()
			conn := k.conn
			k.mu.RUnlock()

			if conn == nil {
				log.Println("Kafka connection lost. Attempting to reconnect...")
				k.reconnect()
				continue
			}

			// Test connection by fetching metadata
			_, err := conn.Brokers()
			if err != nil {
				log.Printf("Kafka connection health check failed: %v. Reconnecting...", err)
				k.reconnect()
			}
		}
	}
}

func (k *kafkaWrapper) reconnect() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.conn != nil {
		k.conn.Close()
	}

	for {
		conn, err := k.dialer.DialContext(k.ctx, "tcp", k.brokers[0])
		if err != nil {
			log.Printf("Failed to reconnect to Kafka: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		k.conn = conn
		k.connected = true
		log.Println("Kafka reconnected successfully")
		break
	}
}

package connections

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"app/src/types"

	"github.com/rabbitmq/amqp091-go"
)

type RabbitMQ interface {
	Connection() *amqp091.Connection
	Channel() (*amqp091.Channel, error)
	PublishMessage(exchange, routingKey string, body []byte) error
	ConsumeMessages(queueName string, handler func(amqp091.Delivery)) error
	DeclareQueue(name string) (amqp091.Queue, error)
	DeclareExchange(name, kind string) error
	Close() error
	IsConnected() bool
}

type rabbitMQWrapper struct {
	connection *amqp091.Connection
	channel    *amqp091.Channel
	ctx        context.Context
	config     types.MainConfig
	url        string
}

func NewRabbitMQ(cfg types.MainConfig) (RabbitMQ, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s/%s",
		cfg.RabbitMQ.Username,
		cfg.RabbitMQ.Password,
		cfg.RabbitMQ.Host,
		strconv.Itoa(cfg.RabbitMQ.Port),
		cfg.RabbitMQ.VHost,
	)

	conn, err := amqp091.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	wrapper := &rabbitMQWrapper{
		connection: conn,
		channel:    ch,
		ctx:        context.Background(),
		config:     cfg,
		url:        url,
	}

	// Setup connection recovery
	go wrapper.handleReconnection()

	return wrapper, nil
}

func (r *rabbitMQWrapper) Connection() *amqp091.Connection {
	return r.connection
}

func (r *rabbitMQWrapper) Channel() (*amqp091.Channel, error) {
	if r.channel == nil || r.channel.IsClosed() {
		ch, err := r.connection.Channel()
		if err != nil {
			return nil, fmt.Errorf("failed to create channel: %w", err)
		}
		r.channel = ch
	}
	return r.channel, nil
}

func (r *rabbitMQWrapper) PublishMessage(exchange, routingKey string, body []byte) error {
	ch, err := r.Channel()
	if err != nil {
		return err
	}

	return ch.Publish(
		exchange,
		routingKey,
		false, // mandatory
		false, // immediate
		amqp091.Publishing{
			ContentType:  "application/json",
			Body:         body,
			Timestamp:    time.Now(),
			DeliveryMode: amqp091.Persistent,
		},
	)
}

func (r *rabbitMQWrapper) ConsumeMessages(queueName string, handler func(amqp091.Delivery)) error {
	ch, err := r.Channel()
	if err != nil {
		return err
	}

	msgs, err := ch.Consume(
		queueName,
		"",    // consumer
		false, // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		return fmt.Errorf("failed to register consumer: %w", err)
	}

	go func() {
		for msg := range msgs {
			handler(msg)
		}
	}()

	return nil
}

func (r *rabbitMQWrapper) DeclareQueue(name string) (amqp091.Queue, error) {
	ch, err := r.Channel()
	if err != nil {
		return amqp091.Queue{}, err
	}

	return ch.QueueDeclare(
		name,
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
}

func (r *rabbitMQWrapper) DeclareExchange(name, kind string) error {
	ch, err := r.Channel()
	if err != nil {
		return err
	}

	return ch.ExchangeDeclare(
		name,
		kind,
		true,  // durable
		false, // auto-deleted
		false, // internal
		false, // no-wait
		nil,   // arguments
	)
}

func (r *rabbitMQWrapper) Close() error {
	if r.channel != nil {
		r.channel.Close()
	}
	if r.connection != nil {
		return r.connection.Close()
	}
	return nil
}

func (r *rabbitMQWrapper) IsConnected() bool {
	return r.connection != nil && !r.connection.IsClosed()
}

func (r *rabbitMQWrapper) handleReconnection() {
	for {
		reason, ok := <-r.connection.NotifyClose(make(chan *amqp091.Error))
		if !ok {
			break
		}

		log.Printf("RabbitMQ connection closed: %v. Reconnecting...", reason)

		for {
			time.Sleep(5 * time.Second)

			conn, err := amqp091.Dial(r.url)
			if err != nil {
				log.Printf("Failed to reconnect to RabbitMQ: %v", err)
				continue
			}

			ch, err := conn.Channel()
			if err != nil {
				log.Printf("Failed to open channel after reconnection: %v", err)
				conn.Close()
				continue
			}

			r.connection = conn
			r.channel = ch
			log.Println("RabbitMQ reconnected successfully")
			break
		}
	}
}

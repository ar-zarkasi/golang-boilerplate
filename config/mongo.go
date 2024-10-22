package config

import (
	"app/utils"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func runMongo() {
	err := error(nil)
	mongodb, err = connectMongo()
	utils.ErrorFatal(err)
}

func connectMongo() (*mongo.Database, error) {
	var (
		host = os.Getenv("MONGO_HOST")
		port = os.Getenv("MONGO_PORT")
		dbname = os.Getenv("MONGO_DBNAME")
	)
	// connect to mongo
	clientOptions := options.Client()
	dsn := fmt.Sprintf("mongodb://%s:%s", host, port)
	clientOptions.ApplyURI(dsn)
	client, err := mongo.Connect(clientOptions)

	db := client.Database(dbname)
	return db, err
}

func GetMongo() *mongo.Database {
	return mongodb
}
package utilities

import (
	"context"
	"errors"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoUtil struct {
	host string
	port string
}

func GetDefaultMongoHost() string {
	return os.Getenv("MONGODB_HOST")
}

func GetDefaultMongoPort() string {
	return os.Getenv(("MONGODB_PORT"))
}

func NewMongoUtil(host string, port string) *MongoUtil {
	return &MongoUtil{host, port}
}

func (mu *MongoUtil) GetMongoDb(collectionName string) (context.Context, *mongo.Client, *mongo.Database, *mongo.Collection, error) {
	if mu.host == "" || mu.port == "" {
		return nil, nil, nil, nil, errors.New("host and port not specified; use New function to create this type")
	}
	mongoUrl := fmt.Sprintf("mongodb://%s:%s", mu.host, mu.port)
	clientOptions := options.Client().ApplyURI((mongoUrl))
	client, err := mongo.NewClient(clientOptions)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ctx := context.Background()
	err = client.Connect(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	database := client.Database(os.Getenv("MONGODB_DATABASE_NAME"))
	collection := database.Collection(collectionName)
	return ctx, client, database, collection, nil
}

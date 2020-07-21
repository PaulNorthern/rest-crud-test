package config

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
)

func GetDBCollection() (*mongo.Collection, error) {
	// Use clinet
	clientOptions := options.Client().ApplyURI("mongodb+srv://admin:admin@cluster0.kjh09.mongodb.net/go_rest_api?retryWrites=true&w=majority")
	// Connect to DB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	collection := client.Database("go_rest_api").Collection("test_task_golang")
	return collection, nil
}

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type Result struct {
	InvokeCount int      `json:"InvokeCount"`
	Objects     []string `json:"Objects"`
}

var invokeCount int
var myObjects []types.Object

func init() {
	// Load the SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	// Initialize an S3 client
	svc := s3.NewFromConfig(cfg)

	// Define the bucket name as a variable so we can take its address
	bucketName := "asteurer-fermyon-lambda-test"
	input := &s3.ListObjectsV2Input{
		Bucket: &bucketName,
	}

	// List objects in the bucket
	result, err := svc.ListObjectsV2(context.TODO(), input)
	if err != nil {
		log.Fatalf("Failed to list objects: %v", err)
	}
	myObjects = result.Contents
}

func LambdaHandler(ctx context.Context) (Result, error) {
	invokeCount++
	var strings []string
	for i, obj := range myObjects {
		entry := fmt.Sprintf("object[%d] size: %d key: %s", i, obj.Size, *obj.Key)
		strings = append(strings, entry)
	}

	return Result{InvokeCount: invokeCount, Objects: strings}, nil
}

func main() {
	lambda.Start(LambdaHandler)
}

package spin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	spinVars "github.com/fermyon/spin/sdk/go/v2/variables"
)

type Result struct {
	InvokeCount int      `json:"InvokeCount"`
	Objects     []string `json:"Objects"`
}

var invokeCount int
var myObjects []types.Object

func processEvent(ctx context.Context) {
	accessKeyId, err := spinVars.Get("access_key_id")
	if err != nil {
		log.Printf("Failed to retrieve access_key_id: %v", err)
	}

	secretAccessKey, err := spinVars.Get("secret_access_key: %v")
	if err != nil {
		log.Printf("Failed to retrieve secret_access_key: %v", err)
	}

	sessionToken, err := spinVars.Get("session_token")
	if err != nil {
		log.Printf("Failed to retrieve session_token: %v", err)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     accessKeyId,
				SecretAccessKey: secretAccessKey,
				SessionToken:    sessionToken,
			},
		}))
	if err != nil {
		log.Fatal(err)
	}

	// Initialize an S3 client
	svc := s3.NewFromConfig(cfg)

	// Define the bucket name as a variable so we can take its address
	bucketName, err := spinVars.Get("bucket_name")
	if err != nil {
		log.Printf("Failed to retrieve bucket_name: %v", err)
	}

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

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		invokeCount++
		var objects []string
		for i, obj := range myObjects {
			entry := fmt.Sprintf("object[%d] size: %d key: %s", i, obj.Size, *obj.Key)
			objects = append(objects, entry)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(Result{InvokeCount: invokeCount, Objects: objects}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func main() {}

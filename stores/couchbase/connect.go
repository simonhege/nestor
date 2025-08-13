package couchbase

import (
	"fmt"
	"os"
	"time"

	"github.com/couchbase/gocb/v2"
)

func Connect() (scope *gocb.Scope, closeFunc func() error, err error) {
	// Update this to your cluster details
	connectionString := os.Getenv("COUCHBASE_CONNECTION_STRING")
	username := os.Getenv("COUCHBASE_USERNAME")
	password := os.Getenv("COUCHBASE_PASSWORD")

	options := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			Username: username,
			Password: password,
		},
	}

	// Sets a pre-configured profile called "wan-development" to help avoid latency issues
	// when accessing Capella from a different Wide Area Network
	// or Availability Zone (e.g. your laptop).
	if err := options.ApplyProfile(gocb.ClusterConfigProfileWanDevelopment); err != nil {
		return nil, nil, fmt.Errorf("failed to apply profile: %w", err)
	}

	// Initialize the Connection
	cluster, err := gocb.Connect(connectionString, options)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %w", err)
	}

	bucketName := os.Getenv("COUCHBASE_BUCKET")
	if bucketName == "" {
		bucketName = "nestor"
	}
	bucket := cluster.Bucket(bucketName)

	err = bucket.WaitUntilReady(5*time.Second, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("bucket connection timeout: %w", err)
	}

	if _, err := bucket.Ping(nil); err != nil {
		return nil, nil, fmt.Errorf("failed to ping bucket: %w", err)
	}

	scopeName := os.Getenv("COUCHBASE_SCOPE")
	if scopeName == "" {
		scopeName = "nestor"
	}
	scope = bucket.Scope(scopeName)
	return scope, func() error {
		return cluster.Close(nil)
	}, nil
}

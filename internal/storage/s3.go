// Package storage puts and gets attachment bytes in an S3-compatible bucket.
// Everything above it — the email package, the HTTP handlers, the worker —
// talks to the Store interface, never to the AWS SDK, so a bucket, a
// self-hosted MinIO, or Cloudflare R2 are the same code path.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ErrNotConfigured means no bucket is set. Attachment infrastructure exists
// end to end — schema, service, worker — before real credentials do; a
// deployment without S3_BUCKET set answers uploads with 503 instead of
// panicking at boot, so the rest of the API keeps working while the bucket
// is provisioned separately.
var ErrNotConfigured = errors.New("storage: S3 is not configured")

// Store puts and gets objects by key. Small enough to fake in tests.
type Store interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// S3Store implements Store against any S3-compatible API.
type S3Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewFromEnv builds a Store from S3_BUCKET, S3_REGION, and optionally
// S3_ENDPOINT (for MinIO, R2, or anything that is not AWS itself),
// S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY, S3_FORCE_PATH_STYLE and
// S3_PREFIX.
//
// S3_PREFIX lets development and production share one bucket without being
// able to touch each other's objects. It is deliberately applied here rather
// than baked into the keys the database stores: a row records where the
// object is within a deployment, and moving a deployment to a different
// prefix must not require rewriting every row.
//
// Returns ErrNotConfigured when S3_BUCKET is empty, which is the expected
// state until credentials are filled in — callers decide whether that is
// fatal (attachments unavailable) or fine (nothing needs them yet).
func NewFromEnv(ctx context.Context) (*S3Store, error) {
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		return nil, ErrNotConfigured
	}

	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(region))

	if key, secret := os.Getenv("S3_ACCESS_KEY_ID"), os.Getenv("S3_SECRET_ACCESS_KEY"); key != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(key, secret, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage: load AWS config: %w", err)
	}

	forcePathStyle, _ := strconv.ParseBool(os.Getenv("S3_FORCE_PATH_STYLE"))
	endpoint := os.Getenv("S3_ENDPOINT")

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			// Non-AWS S3-compatible endpoints (MinIO, R2, Backblaze B2, ...)
			// need the bucket in the path rather than as a subdomain.
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = forcePathStyle
		}
	})

	// A prefix names a directory, so tolerate it being given with or without
	// the trailing slash. "dev" and "dev/" must not be two different places.
	prefix := os.Getenv("S3_PREFIX")
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/") + "/"
	}

	return &S3Store{client: client, bucket: bucket, prefix: prefix}, nil
}

// path places a caller's key inside this deployment's prefix. Every request
// to the bucket goes through it, so no code path can escape the prefix by
// forgetting to prepend it.
func (s *S3Store) path(key string) string { return s.prefix + key }

func (s *S3Store) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.path(key)),
		Body:          r,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("storage: put %s: %w", key, err)
	}
	return nil
}

func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.path(key)),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: get %s: %w", key, err)
	}
	return out.Body, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.path(key)),
	})
	if err != nil {
		return fmt.Errorf("storage: delete %s: %w", key, err)
	}
	return nil
}

// Compile-time proof S3Store satisfies Store.
var _ Store = (*S3Store)(nil)

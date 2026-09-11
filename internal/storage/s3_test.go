package storage

import (
	"context"
	"testing"
)

// The prefix is what keeps development and production apart inside one
// bucket, so it has to be exact: a missing separator would make dev write to
// "devattachments/..." — still wrong, but silently, and next to production's
// objects rather than under a directory of its own.
func TestPrefixIsNormalisedToADirectory(t *testing.T) {
	for name, prefix := range map[string]string{
		"with a trailing slash":    "dev/",
		"without a trailing slash": "dev",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("S3_BUCKET", "heromail")
			t.Setenv("S3_PREFIX", prefix)

			s, err := NewFromEnv(context.Background())
			if err != nil {
				t.Fatalf("NewFromEnv: %v", err)
			}
			if got := s.path("attachments/abc"); got != "dev/attachments/abc" {
				t.Errorf("path = %q, want %q", got, "dev/attachments/abc")
			}
		})
	}
}

// An unset prefix must mean the bucket root, not a leading slash: "/key" and
// "key" are different objects in S3.
func TestNoPrefixLeavesKeysUntouched(t *testing.T) {
	t.Setenv("S3_BUCKET", "heromail")
	t.Setenv("S3_PREFIX", "")

	s, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if got := s.path("attachments/abc"); got != "attachments/abc" {
		t.Errorf("path = %q, want %q", got, "attachments/abc")
	}
}

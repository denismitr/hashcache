package hashcache

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestHeader_String(t *testing.T) {
	clock = func() time.Time {
		now, err := time.Parse(time.RFC3339, "2024-01-02T15:04:05Z")
		if err != nil {
			t.Fatal(err)
		}
		return now
	}

	randomizer = func(n int) (string, error) {
		s := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", defaultRandBytesNum)))
		return s, nil
	}

	t.Run("default", func(t *testing.T) {
		h, err := New("my.email@gmail.com", 3, 90*time.Second)
		require.NoError(t, err)
		assert.Equal(t, "1:3:1704207935000000000:bXkuZW1haWxAZ21haWwuY29t:sha-1:YWFhYWFhYWFhYQ==:0", h.String())
	})

	t.Run("default with ip address and days of expiration", func(t *testing.T) {
		h, err := New("127.0.0.1:9983", 3, 90*time.Hour)
		require.NoError(t, err)
		assert.Equal(t, "1:3:1704531845000000000:MTI3LjAuMC4xOjk5ODM=:sha-1:YWFhYWFhYWFhYQ==:0", h.String())
	})
}

func TestParse(t *testing.T) {
	t.Parallel()

	tt := []struct {
		in  string
		out Header
		err error
	}{
		{
			in:  "1:20:1665396610:bG9jYWxob3N0:sha-256:vZOxuoIgixP+hw==:AAAAAAAAAAA=",
			out: Header{Ver: 1, ZeroBits: 20, Expiration: 1665396610, Resource: "localhost", Algorithm: algSha256},
		},
	}

	for i, tc := range tt {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			h, err := Parse(tc.in)
			if tc.err == nil && err != nil {
				t.Fatalf("unexpected error %v", err)
			} else if tc.err != nil && err == nil {
				t.Fatalf("expected an error %v but got nil", tc.err)
			}

			if diff := cmp.Diff(tc.out, h); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestHeader_Compute(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		h, err := New("my.email@gmail.com", 3, 90*time.Second)
		require.NoError(t, err)
		computed, err := Compute(ctx, h, 0)
		require.NoError(t, err)
		assert.Greater(t, int(computed.Counter), 100)
		assert.True(t, computed.Valid())
	})
}

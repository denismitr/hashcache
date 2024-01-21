package hashcache

import (
	"context"
	"encoding/base64"
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

package hashcache

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultVersion      = 1
	defaultRandBytesNum = 10

	headerStringSeparator = ":"
)

var (
	ErrRandomFailed        = errors.New("random generation failed")
	ErrTooManyIterations   = errors.New("too many iterations")
	ErrInvalidHeaderString = errors.New("invalid header string")
)

var (
	clock      = time.Now
	randomizer = randBase64
)

// Header of a hashcash is a cryptographic hash-based proof-of-work algorithm
// that requires a selectable amount of work to compute,
// but the proof can be verified efficiently.
// https://en.wikipedia.org/wiki/Hashcash
type Header struct {
	// Resource data string being transmitted, e.g., an IP address or email address.
	Resource string

	// Algorithm is a type of algorithm used
	Algorithm string

	// String of random characters, encoded in base-64 format.
	Rand string

	// The time that the message was sent, in the format YYMMDD[hhmm[ss]]
	Expiration int64

	// Binary counter, encoded in base-64 format.
	Counter uint64

	// format version, 1 (which supersedes version 0).
	Ver uint8

	// Number of "partial pre-image" (zero) bits in the hashed code.
	ZeroBits uint8
}

func New(resource string, zeroBits uint8, ttl time.Duration) (Header, error) {
	randEncoded, err := randomizer(defaultRandBytesNum)
	if err != nil {
		return Header{}, err
	}

	return Header{
		Ver:        defaultVersion,
		ZeroBits:   zeroBits,
		Resource:   base64.StdEncoding.EncodeToString([]byte(resource)),
		Rand:       randEncoded,
		Algorithm:  algSha1,
		Expiration: clock().Add(ttl).UnixNano(),
		Counter:    0,
	}, nil
}

func (h Header) String() string {
	return fmt.Sprintf(
		"%d:%d:%d:%s:%s:%s:%d",
		h.Ver, h.ZeroBits, h.Expiration, h.Resource, h.Algorithm, h.Rand, h.Counter,
	)
}

func (h Header) Valid() bool {
	return verify(h.Hash(), h.ZeroBits)
}

func (h Header) Hash() string {
	hasher := resolveHash(h.Algorithm)
	hasher.Write([]byte(h.String()))
	return hex.EncodeToString(hasher.Sum(nil))
}

func verify(hash string, zeroBits uint8) bool {
	if int(zeroBits) > len(hash) {
		return false
	}

	for i := range hash[:zeroBits] {
		if hash[i] != 0x30 {
			return false
		}
	}

	return true
}

// Compute the useful work according to the header
func Compute(ctx context.Context, h Header, maxIterations int) (Header, error) {
	for counter := int(h.Counter); counter <= maxIterations || maxIterations <= 0; counter++ {
		if ctx.Err() != nil {
			return Header{}, ctx.Err()
		}

		if h.Valid() {
			return h, nil
		}

		h.Counter++
	}

	return Header{}, ErrTooManyIterations
}

func Parse(header string) (Header, error) {
	var h Header

	tokens := strings.Split(header, headerStringSeparator)
	if len(tokens) < 7 {
		return h, ErrInvalidHeaderString
	}

	version, err := strconv.Atoi(tokens[0])
	if err != nil {
		return h, fmt.Errorf("%w: invalid version '%s'", ErrInvalidHeaderString, tokens[0])
	}

	if version > math.MaxUint8 || version < 0 {
		return h, fmt.Errorf("%w: invalid version '%d'", ErrInvalidHeaderString, version)
	}

	zeroBits, err := strconv.Atoi(tokens[1])
	if err != nil {
		return h, fmt.Errorf("%w: invalid zero bits '%s'", ErrInvalidHeaderString, tokens[1])
	}

	if zeroBits > math.MaxUint8 || zeroBits < 0 {
		return h, fmt.Errorf("%w: invalid zero bits '%d'", ErrInvalidHeaderString, zeroBits)
	}

	expiration, err := strconv.ParseInt(tokens[2], 10, 64)
	if err != nil {
		return h, fmt.Errorf("%w: invalid expiration '%s'", ErrInvalidHeaderString, tokens[2])
	}

	resource, err := base64.StdEncoding.DecodeString(tokens[3])
	if err != nil {
		return h, fmt.Errorf("%w: invalid base64 encoded resource '%s'", ErrInvalidHeaderString, tokens[3])
	}

	alg := tokens[4]
	if !slices.Contains(algorithms, alg) {
		return h, fmt.Errorf("%w: unsupported algorithm '%s'", ErrInvalidHeaderString, alg)
	}

	return Header{
		Ver:        uint8(version),
		ZeroBits:   uint8(zeroBits),
		Expiration: expiration,
		Resource:   string(resource),
		Algorithm:  alg,
	}, nil
}

func resolveHash(alg string) hash.Hash {
	switch alg {
	case "sha-256":
		return sha256.New()
	case "sha-512":
		return sha256.New()
	case "sha-1":
		return sha1.New()
	default:
		return sha1.New()
	}
}

func randBase64(n int) (string, error) {
	buf := make([]byte, n)

	if _, err := rand.Read(buf); err != nil {
		return "", errors.Join(ErrRandomFailed, err)
	}

	encoded := base64.StdEncoding.EncodeToString(buf)
	return encoded, nil
}

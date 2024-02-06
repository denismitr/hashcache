package hashcache

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	algSha1   = "sha-1"
	algSha256 = "sha-256"
	algSha512 = "sha-512"
)

var algorithms = []string{algSha1, algSha256, algSha512}

func resolveHash(alg string) hash.Hash {
	switch alg {
	case algSha256:
		return sha256.New()
	case algSha512:
		return sha512.New()
	case algSha1:
		return sha1.New()
	default:
		return sha1.New()
	}
}

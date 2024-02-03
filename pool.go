package hashcache

import (
	"context"
	"sync"
	"time"
)

const (
	defaultPoolConcurrency = 10
)

type PoolConfig struct {
	Concurrency   int
	MaxIterations int
	Timeout       time.Duration
}

type ComputeResult struct {
	Time   time.Duration
	Header Header
}

type PoolOption func(*PoolConfig)

func ComputeWithPool(
	baseCtx context.Context,
	header Header,
	opts ...PoolOption,
) (ComputeResult, error) {
	var ctx context.Context
	var cancel context.CancelFunc

	cfg := PoolConfig{Concurrency: defaultPoolConcurrency}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Timeout > 0 {
		ctx, cancel = context.WithTimeout(baseCtx, cfg.Timeout)
	} else {
		ctx, cancel = context.WithCancel(baseCtx)
	}

	defer cancel()

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)

	resultCh := make(chan Header, 1)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	counter := int(header.Counter)

	for i := 0; i < cfg.Concurrency; i++ {
		go func(i int) {
			defer wg.Done()

			chunkSize := cfg.MaxIterations / cfg.Concurrency
			sincePos := counter + i*chunkSize
			if i > 0 {
				sincePos += i
			}

			untilPos := sincePos + chunkSize
			if untilPos > cfg.MaxIterations {
				untilPos = cfg.MaxIterations
			}

			chunkHeader := header
			chunkHeader.Counter = uint64(sincePos)

			calc, err := Compute(ctx, chunkHeader, untilPos)
			if err != nil {
				return
			}

			resultCh <- calc
		}(i)
	}

	computeResult := ComputeResult{}
	for result := range resultCh {
		if result.Valid() {
			computeResult.Time = time.Since(start)
			computeResult.Header = result
			return computeResult, nil
		}
	}

	select {
	case <-ctx.Done():
		return computeResult, ctx.Err()
	default:
	}

	return computeResult, ErrTooManyIterations
}

// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"context"
	"log"
	"sync"
	"time"
)

type pooledCredentialProvider struct {
	base     CredentialProvider
	poolSize int
	logger   *log.Logger

	mu      sync.Mutex
	creds   []TurnCredentials
	created time.Time
	next    int
}

func PoolCredentials(base CredentialProvider, poolSize int, logger *log.Logger) CredentialProvider {
	if poolSize <= 1 {
		return base
	}

	return &pooledCredentialProvider{
		base:     base,
		poolSize: poolSize,
		logger:   getLogger(logger),
	}
}

func (p *pooledCredentialProvider) GetCredentials(ctx context.Context, inviteLink string) (TurnCredentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.created.IsZero() && time.Since(p.created) > 10*time.Minute {
		p.creds = nil
		p.created = time.Time{}
	}

	if len(p.creds) < p.poolSize {
		creds, err := p.base.GetCredentials(ctx, inviteLink)
		if err == nil {
			p.creds = append(p.creds, creds)
			p.created = time.Now()
			p.logger.Printf("successfully registered user identity %d/%d", len(p.creds), p.poolSize)
			if len(p.creds) < p.poolSize {
				time.Sleep(time.Second)
			}
			return p.takeNextLocked(), nil
		}

		p.logger.Printf("failed to get unique TURN identity: %v", err)
		if len(p.creds) > 0 {
			p.logger.Printf("falling back to reusing a previous identity")
			return p.takeNextLocked(), nil
		}

		return TurnCredentials{}, err
	}

	return p.takeNextLocked(), nil
}

func (p *pooledCredentialProvider) takeNextLocked() TurnCredentials {
	creds := p.creds[p.next%len(p.creds)]
	p.next++
	return creds
}

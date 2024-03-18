package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// const DefaultAcmeDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory" // Staging endpoint
const DefaultAcmeDirectory = "https://acme-v02.api.letsencrypt.org/directory"

type Acme struct {
	Directory  string
	AccountKey crypto.Signer
	Logger     *zap.Logger
	AlbArn     string
}

func (a Acme) GetCertificate(ctx context.Context, domains []string) (crypto.Signer, []byte, error) {
	client := acmez.Client{
		Client: &acme.Client{
			Directory: a.Directory,
			Logger:    a.Logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01: AlbHttp01Solver{
				AlbArn:  a.AlbArn,
				Domains: domains,
				Logger:  a.Logger,
			},
		},
	}

	// NewAccount would load an existing account if one exists
	account, err := client.NewAccount(ctx, acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           a.AccountKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("new account: %v", err)
	}

	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating certificate key: %v", err)
	}

	certs, err := client.ObtainCertificate(ctx, account, certPrivateKey, domains)
	if err != nil {
		return nil, nil, fmt.Errorf("obtaining certificate: %v", err)
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates obtained")
	}

	// Simple cert chain selection strategy: pick the first one
	return certPrivateKey, certs[0].ChainPEM, nil

}

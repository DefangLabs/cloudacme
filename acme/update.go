package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/defang-io/cloudacme/aws/acm"
	"github.com/defang-io/cloudacme/aws/alb"
	"github.com/defang-io/cloudacme/solver"
	"github.com/mholt/acmez"
	"go.uber.org/zap"
)

var ChallengeSolver acmez.Solver
var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Panicf("failed to create logger: %v", err)
	}
}

func UpdateAcmeCertificate(ctx context.Context, albArn, domain string) error {
	accountKey, err := getAccountKey()
	if err != nil {
		return fmt.Errorf("failed to get account key: %w", err)
	}

	// Find the certificate to update from all the certificates attached to the ALB
	certArns, err := alb.GetAlbCerts(ctx, albArn)
	if err != nil {
		return fmt.Errorf("failed to get ALB certificates: %w", err)
	}

	var getCertErrs []error
	certToUpdate := ""
	for _, certArn := range certArns {
		certPem, err := acm.GetCertificate(ctx, certArn)
		if err != nil {
			getCertErrs = append(getCertErrs, err)
			continue
		}
		block, _ := pem.Decode([]byte(certPem))
		if block == nil {
			getCertErrs = append(getCertErrs, fmt.Errorf("failed to decode certificate pem for %v", certArn))
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			getCertErrs = append(getCertErrs, fmt.Errorf("failed to parse certificate for %v: %w", certArn, err))
			continue
		}
		if cert.Subject.CommonName == domain {
			// TODO: check the issuer and expiration date
			// TODO: should we check SANs? probably not, as byod domain are added as SNI single domain certs
			certToUpdate = certArn
			break
		}
	}
	if certToUpdate == "" {
		if len(getCertErrs) == 0 {
			return fmt.Errorf("no certificate matching %v found", domain)
		}
		return fmt.Errorf("failed to get certificate: %w", errors.Join(getCertErrs...))
	}

	acmeDirectory := os.Getenv("ACME_DIRECTORY")
	if acmeDirectory == "" {
		acmeDirectory = DefaultAcmeDirectory
	}

	cs := ChallengeSolver
	if cs == nil {
		cs = solver.AlbHttp01Solver{
			AlbArn:  albArn,
			Domains: []string{domain},
			Logger:  logger,
		}
	}
	acmeClient := Acme{
		Directory:  acmeDirectory,
		AccountKey: accountKey,
		Logger:     logger,
		AlbArn:     albArn,
		HttpSolver: cs,
	}

	key, chain, err := acmeClient.GetCertificate(ctx, []string{domain})
	if err != nil {
		return fmt.Errorf("failed to get certificates: %w", err)
	}

	if err := acm.ImportCertificate(ctx, key, chain, certToUpdate); err != nil {
		return fmt.Errorf("error importing certificate: %w", err)
	}
	return nil
}

func getAccountKey() (*ecdsa.PrivateKey, error) {

	accountKeyPem := os.Getenv("ACME_ACCOUNT_KEY")
	if accountKeyPem == "" {
		return nil, fmt.Errorf("ACME_ACCOUNT_KEY environment variable not set")
	}
	block, _ := pem.Decode([]byte(accountKeyPem)) // 2nd return value is not err, is the remaining data
	if block == nil {
		return nil, fmt.Errorf("failed to decode account key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse account key: %v", err)
	}
	return key, nil
}

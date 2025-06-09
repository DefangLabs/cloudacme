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

	"github.com/DefangLabs/cloudacme/aws/acm"
	"github.com/DefangLabs/cloudacme/aws/alb"
	awsalb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/mholt/acmez"
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Panicf("failed to create logger: %v", err)
	}
}

func UpdateAcmeCertificate(ctx context.Context, albArn, domain string, solver acmez.Solver) error {
	accountKey, err := getAccountKey()
	if err != nil {
		return fmt.Errorf("failed to get account key: %w", err)
	}

	certToUpdate, _, err := GetExistingCertificate(ctx, albArn, domain)
	if err != nil {
		return fmt.Errorf("failed to get existing certificate: %w", err)
	}

	acmeDirectory := os.Getenv("ACME_DIRECTORY")
	if acmeDirectory == "" {
		acmeDirectory = DefaultAcmeDirectory
	}

	acmeClient := Acme{
		Directory:  acmeDirectory,
		AccountKey: accountKey,
		Logger:     logger,
		AlbArn:     albArn,
		HttpSolver: solver,
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

func GetExistingCertificate(ctx context.Context, albArn, domain string) (string, *x509.Certificate, error) {
	// Find the certificate to update from all the certificates attached to the ALB
	certArns, err := alb.GetAlbCerts(ctx, albArn)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get ALB certificates: %w", err)
	}

	var getCertErrs []error
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
			return certArn, cert, nil
		}
	}
	return "", nil, fmt.Errorf("no certificate matching %v found: %w", domain, errors.Join(getCertErrs...))
}

func SetupHttpRule(ctx context.Context, albArn, lambdaArn string, ruleCond alb.RuleCondition) error {
	listener, err := alb.GetListener(ctx, albArn, awsalb.ProtocolEnumHttp, 80)
	if err != nil {
		return fmt.Errorf("cannot get http listener: %w", err)
	}

	targetGroupArn, err := alb.GetLambdaTargetGroup(ctx, lambdaArn)
	if err != nil {
		return fmt.Errorf("cannot get target group for lambda %v: %w", lambdaArn, err)
	}

	if err := alb.AddListenerTriggerTargetGroupRule(ctx, *listener.ListenerArn, ruleCond, targetGroupArn); err != nil {
		return fmt.Errorf("failed to create listener static rule: %w", err)
	}
	return nil
}

func RemoveHttpRule(ctx context.Context, albArn string, ruleCond alb.RuleCondition) error {
	listener, err := alb.GetListener(ctx, albArn, awsalb.ProtocolEnumHttp, 80)
	if err != nil {
		return fmt.Errorf("cannot get http listener: %w", err)
	}
	if err := alb.DeleteListenerPathRule(ctx, *listener.ListenerArn, ruleCond); err != nil {
		return fmt.Errorf("failed to delete listener static rule: %w", err)
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

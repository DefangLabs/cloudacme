package main

import (
	"context"
	"log"

	"github.com/DefangLabs/cloudacme/acme"
	"github.com/DefangLabs/cloudacme/aws/acm"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

var version = "dev" // to be set by ldflags

func main() {

	var debug *bool = pflag.Bool("debug", false, "Enable debug logging")
	var certArn *string = pflag.String("cert-arn", "", "ARN of the certificate to reimport to")
	var accountKeyFile *string = pflag.String("account-key-file", "./acme_account_key.pem", "Path to the account key file in PEM format, a new key will be generated and saved to this path if it does not exist")
	var accountKeySSM *string = pflag.String("account-key-ssm", "", "Name of the AWS SSM parameter to load from and store the account key to, if not provided the key will be saved to local file")
	var acmeDirectory *string = pflag.String("directory", acme.DefaultAcmeDirectory, "ACME directory URL")
	var domain *string = pflag.String("domain", "", "Domain to request certificate for")
	var albArn *string = pflag.String("alb-arn", "", "ARN of the ALB to update")
	pflag.Parse()

	if *domain == "" {
		log.Fatalf("domain is required")
	}

	if *certArn == "" {
		log.Fatalf("cert-arn is required")
	}

	if *albArn == "" {
		log.Fatalf("alb-arn is required")
	}

	var logger *zap.Logger
	var err error
	if *debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}

	ctx := context.Background()

	var keyStore acme.AccountKeyStore

	if *accountKeySSM != "" {
		keyStore = acme.SSMAccountKeyStore{Name: *accountKeySSM}
	} else {
		keyStore = acme.FileAccountKeyStore{Path: *accountKeyFile}
	}

	accountPrivateKey, err := acme.LoadOrCreateAccountKey(ctx, keyStore)

	acmeClient := acme.Acme{
		Directory:  *acmeDirectory,
		AccountKey: accountPrivateKey,
		Logger:     logger,
		AlbArn:     *albArn,
	}

	key, chain, err := acmeClient.GetCertificate(ctx, []string{*domain})
	if err != nil {
		log.Fatalf("Failed to get certificates: %v", err)
	}

	if err := acm.ImportCertificate(ctx, key, chain, *certArn); err != nil {
		log.Printf("Error importing certificate: %v", err)
	}

}

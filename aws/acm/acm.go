package acm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/defang-io/cloudacme/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func ImportCertificate(ctx context.Context, privateKey crypto.PrivateKey, certChainPem []byte, certArn string) error {
	svc := acm.NewFromConfig(aws.LoadConfig())

	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	certsPem := bytes.Split(certChainPem, []byte("\n\n"))

	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})

	var arn *string
	if certArn != "" {
		arn = &certArn
	}

	input := &acm.ImportCertificateInput{
		Certificate:      certsPem[0],
		PrivateKey:       privateKeyPem,
		CertificateChain: certChainPem,
		CertificateArn:   arn,
	}

	if _, err := svc.ImportCertificate(ctx, input); err != nil {
		return err
	}

	return nil
}

func GetCertificate(ctx context.Context, certArn string) ([]byte, error) {
	svc := acm.NewFromConfig(aws.LoadConfig())

	input := &acm.GetCertificateInput{
		CertificateArn: &certArn,
	}

	output, err := svc.GetCertificate(ctx, input)
	if err != nil {
		return nil, err
	}

	return []byte(*output.Certificate), nil
}

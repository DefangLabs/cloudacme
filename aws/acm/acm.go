package acm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"defang.io/acme/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func ImportCertificate(ctx context.Context, cert *tls.Certificate, certArn string) error {
	svc := acm.NewFromConfig(aws.LoadConfig())

	privateKey, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	chain := EncodeCertifciateChain(cert.Certificate)

	var arn *string
	if certArn != "" {
		arn = &certArn
	}

	input := &acm.ImportCertificateInput{
		Certificate:      certPem,
		PrivateKey:       privateKeyPem,
		CertificateChain: chain,
		CertificateArn:   arn,
	}

	out, err := svc.ImportCertificate(ctx, input)
	if err != nil {
		return err
	}

	fmt.Printf("Imported certificate: %v\n", out.CertificateArn)
	fmt.Printf("Import output: %+v\n", out)
	return nil
}

func EncodeCertifciateChain(chain [][]byte) []byte {
	var chainBuf bytes.Buffer
	for _, cert := range chain {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		chainBuf.Write(pemCert)
	}
	return chainBuf.Bytes()
}

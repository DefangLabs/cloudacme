package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"

	"defang.io/cloudacme/acme"
	"defang.io/cloudacme/aws/acm"
	"defang.io/cloudacme/aws/alb"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsalb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"go.uber.org/zap"
)

var version = "dev" // to be set by ldflags

type CertificateRenewalEvent struct {
	Domain string `json:"domain"`
	AlbArn string `json:"albArn"`
}

type Event struct {
	events.ALBTargetGroupRequest
	CertificateRenewalEvent
}

var logger *zap.Logger

func HandleEvent(ctx context.Context, evt Event) (any, error) {
	log.Printf("cloudacme version %v", version)
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	if evt.HTTPMethod != "" {
		return HandleALBEvent(ctx, evt.ALBTargetGroupRequest)
	} else {
		return nil, HandleEventBridgeEvent(ctx, evt.CertificateRenewalEvent)
	}
}

func HandleALBEvent(ctx context.Context, evt events.ALBTargetGroupRequest) (*events.ALBTargetGroupResponse, error) {
	log.Printf("Handling ALB Event: %+v", evt)

	targetGroupArn := evt.RequestContext.ELB.TargetGroupArn
	albArn, err := alb.GetTargetGroupAlb(ctx, targetGroupArn)
	if err != nil {
		return nil, fmt.Errorf("failed to get ALB ARN from target group %v: %w", targetGroupArn, err)
	}

	host := evt.Headers["host"]
	if err := updateAcmeCertificate(ctx, albArn, host); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	cond := alb.RuleCondition{
		HostHeader:  []string{host},
		PathPattern: []string{"/"},
	}

	if err := removeHttpRule(ctx, albArn, cond); err != nil {
		return nil, fmt.Errorf("failed to remove http rule: %w", err)
	}

	return &events.ALBTargetGroupResponse{
		StatusCode: 301,
		Headers: map[string]string{
			"Location": getHttpsRedirectURL(evt),
		},
	}, nil
}

func removeHttpRule(ctx context.Context, albArn string, ruleCond alb.RuleCondition) error {
	listener, err := alb.GetListener(ctx, albArn, awsalb.ProtocolEnumHttp, 80)
	if err != nil {
		return fmt.Errorf("cannot get http listener: %w", err)
	}
	if err := alb.DeleteListenerPathRule(ctx, *listener.ListenerArn, ruleCond); err != nil {
		return fmt.Errorf("failed to delete listener static rule: %w", err)
	}
	return nil
}

func getHttpsRedirectURL(evt events.ALBTargetGroupRequest) string {
	params := ""
	if evt.QueryStringParameters != nil {
		var values url.Values
		for k, v := range evt.QueryStringParameters {
			values.Add(k, v)
		}
		params += values.Encode()
	} else if evt.MultiValueQueryStringParameters != nil {
		values := url.Values(evt.MultiValueQueryStringParameters)
		params += values.Encode()
	}
	if params != "" {
		params = "?" + params
	}
	return fmt.Sprintf("https://%s%s%s", evt.Headers["host"], evt.Path, params)
}

func updateAcmeCertificate(ctx context.Context, albArn, domain string) error {
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
		acmeDirectory = acme.DefaultAcmeDirectory
	}

	acmeClient := acme.Acme{
		Directory:  acmeDirectory,
		AccountKey: accountKey,
		Logger:     logger,
		AlbArn:     albArn,
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

func HandleEventBridgeEvent(ctx context.Context, evt CertificateRenewalEvent) error {
	log.Printf("Handling Certificate Renewal Event: %+v", evt)

	if err := updateAcmeCertificate(ctx, evt.AlbArn, evt.Domain); err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	return nil
}

func main() {
	lambda.Start(HandleEvent)
}

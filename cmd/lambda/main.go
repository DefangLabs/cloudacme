package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/DefangLabs/cloudacme/acme"
	"github.com/DefangLabs/cloudacme/aws/alb"
	"github.com/DefangLabs/cloudacme/solver"
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

func HandleEvent(ctx context.Context, evt Event) (any, error) {
	log.Printf("cloudacme version %v", version)
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
	albSolver := solver.AlbHttp01Solver{
		AlbArn:  albArn,
		Domains: []string{host},
	}

	if err := acme.UpdateAcmeCertificate(ctx, albArn, host, albSolver); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	cond := alb.RuleCondition{
		HostHeader:  []string{host},
		PathPattern: []string{"/"},
	}

	if err := acme.RemoveHttpRule(ctx, albArn, cond); err != nil {
		return nil, fmt.Errorf("failed to remove http rule: %w", err)
	}

	validationCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := validateCertAttached(validationCtx, host); err != nil {
		return nil, fmt.Errorf("failed to validate certificate: %w", err)
	}

	return &events.ALBTargetGroupResponse{
		StatusCode: 301,
		Headers: map[string]string{
			"Location": getHttpsRedirectURL(evt),
		},
	}, nil
}

func validateCertAttached(ctx context.Context, domain string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s", domain), nil)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			if _, err := http.DefaultClient.Do(req); err != nil {
				var tlsErr *tls.CertificateVerificationError
				if errors.As(err, &tlsErr) {
					log.Printf("ssl cert for %v is still not valid: %v", domain, tlsErr)
					continue
				}
				return fmt.Errorf("failed https request to domain %v: %w", domain, err)
			}
			return nil
		}
	}
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

func HandleEventBridgeEvent(ctx context.Context, evt CertificateRenewalEvent) error {
	log.Printf("Handling Certificate Renewal Event: %+v", evt)

	albSolver := solver.AlbHttp01Solver{
		AlbArn:  evt.AlbArn,
		Domains: []string{evt.Domain},
	}

	if err := acme.UpdateAcmeCertificate(ctx, evt.AlbArn, evt.Domain, albSolver); err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	return nil
}

func main() {
	lambda.Start(HandleEvent)
}

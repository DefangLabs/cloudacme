package solver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	awsalb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/DefangLabs/cloudacme/aws/alb"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

const DefaultWaitTimeout = 5 * time.Minute

type AlbHttp01Solver struct {
	AlbArn      string
	Domains     []string
	WaitTimeout time.Duration
	Logger      *zap.Logger
}

func (s AlbHttp01Solver) Present(ctx context.Context, chal acme.Challenge) error {
	s.Logger.Info("Presenting challenge", zap.Strings("domains", s.Domains), zap.String("path", chal.HTTP01ResourcePath()))
	listener, err := alb.GetListener(ctx, s.AlbArn, awsalb.ProtocolEnumHttp, 80)
	if err != nil {
		return fmt.Errorf("cannot get http listener: %w", err)
	}

	ruleCond := alb.RuleCondition{
		HostHeader:  s.Domains,
		PathPattern: []string{chal.HTTP01ResourcePath()},
	}

	if err := alb.AddListenerStaticRule(ctx, *listener.ListenerArn, ruleCond, chal.KeyAuthorization); err != nil {
		return fmt.Errorf("failed to add listener static rule: %v", err)
	}
	return nil
}

func (s AlbHttp01Solver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("Cleaning up challenge for domains %v at path %v", s.Domains, chal.HTTP01ResourcePath())
	listener, err := alb.GetListener(ctx, s.AlbArn, awsalb.ProtocolEnumHttp, 80)
	if err != nil {
		return fmt.Errorf("cannot get http listener: %w", err)
	}

	ruleCond := alb.RuleCondition{
		HostHeader:  s.Domains,
		PathPattern: []string{chal.HTTP01ResourcePath()},
	}

	err = alb.DeleteListenerPathRule(ctx, *listener.ListenerArn, ruleCond)
	if errors.Is(err, alb.ErrRuleNotFound) {
		log.Printf("Challenge rule not found, skipping cleanup alb rule for path: %v", chal.HTTP01ResourcePath())
	} else if err != nil {
		return fmt.Errorf("failed to delete listener static rule: %v", err)
	}
	return nil
}

func (s AlbHttp01Solver) Wait(ctx context.Context, chal acme.Challenge) error {
	log.Printf("Waiting for challenge for domains %v at path %v", s.Domains, chal.HTTP01ResourcePath())
	timeout := s.WaitTimeout
	if timeout == 0 {
		timeout = DefaultWaitTimeout
	}

	chkCtx, cancel := context.WithTimeoutCause(ctx, timeout, fmt.Errorf("timeout waiting for challenge after %v", timeout))
	defer cancel()
	for _, domain := range s.Domains {
		chkUrl := "http://" + domain + chal.HTTP01ResourcePath()
		log.Printf("Checking URL %v", chkUrl)
		if err := checkUrl(chkCtx, chkUrl, chal.KeyAuthorization); err != nil {
			return fmt.Errorf("failed waiting for challenge: %w", err)
		}
	}
	log.Printf("Challenge is ready for domains %v, at path %v", s.Domains, chal.HTTP01ResourcePath())
	return nil
}

func checkUrl(ctx context.Context, url, value string) error {
	// go http client defaults to follow 10 redirects which matches let's encrypt's limit
	client := &http.Client{}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				// ignore errors, like expected tls handshake errors
				continue
			}
			if resp.StatusCode == 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				if string(body) == value {
					return nil
				}
			}
		}
	}
}

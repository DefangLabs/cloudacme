package alb

import (
	"context"
	"errors"
	"fmt"
	"log"

	"defang.io/cloudacme/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go/ptr"
)

var ErrRuleNotFound = errors.New("rule not found")

func DeleteListenerPathRule(ctx context.Context, listenerArn, path string) error {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	searchInput := &elbv2.DescribeRulesInput{
		ListenerArn: &listenerArn,
	}
	rulesOutput, err := svc.DescribeRules(ctx, searchInput)
	if err != nil {
		return err
	}

	ruleArn := ""
	for _, rule := range rulesOutput.Rules {
		log.Printf("Condition: %+v", rule.Conditions)
		if len(rule.Conditions) > 0 && rule.Conditions[0].PathPatternConfig != nil && rule.Conditions[0].PathPatternConfig.Values[0] == path {
			log.Printf("Rule values %+v", rule.Conditions[0].PathPatternConfig.Values[0])
			ruleArn = *rule.RuleArn
			break
		}
	}
	if ruleArn == "" {
		return ErrRuleNotFound
	}

	input := &elbv2.DeleteRuleInput{
		RuleArn: &ruleArn,
	}

	if _, err := svc.DeleteRule(ctx, input); err != nil {
		return err
	}
	return nil
}

func AddListenerStaticRule(ctx context.Context, listenerArn, path, value string, priority int32) error {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	input := &elbv2.CreateRuleInput{
		Actions: []types.Action{
			{
				Type: types.ActionTypeEnumFixedResponse,
				FixedResponseConfig: &types.FixedResponseActionConfig{
					ContentType: ptr.String("text/plain"),
					StatusCode:  ptr.String("200"),
					MessageBody: &value,
				},
			},
		},
		Conditions: []types.RuleCondition{
			{
				Field: ptr.String("path-pattern"),
				PathPatternConfig: &types.PathPatternConditionConfig{
					Values: []string{path},
				},
			},
		},
		ListenerArn: &listenerArn,
		Priority:    ptr.Int32(priority),
	}

	_, err := svc.CreateRule(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

func GetListener(ctx context.Context, albArn string, protocol types.ProtocolEnum, port int32) (*types.Listener, error) {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	input := &elbv2.DescribeListenersInput{
		LoadBalancerArn: &albArn,
	}

	result, err := svc.DescribeListeners(ctx, input)
	if err != nil {
		return nil, err
	}

	for _, listener := range result.Listeners {
		if listener.Protocol == protocol && listener.Port != nil && *listener.Port == port {
			return &listener, nil
		}
	}
	return nil, errors.New("Listener not found")
}

func GetAlbCerts(ctx context.Context, albArn string) ([]string, error) {
	albSvc := elbv2.NewFromConfig(aws.LoadConfig())

	listener, err := GetListener(ctx, albArn, types.ProtocolEnumHttps, 443)
	if err != nil {
		return nil, err
	}

	input := &elbv2.DescribeListenerCertificatesInput{
		ListenerArn: listener.ListenerArn,
	}

	result, err := albSvc.DescribeListenerCertificates(ctx, input)
	if err != nil {
		return nil, err
	}

	certArns := make([]string, 0, len(result.Certificates))
	for _, cert := range result.Certificates {
		certArns = append(certArns, *cert.CertificateArn)
	}
	return certArns, nil
}

func GetTargetGroupAlb(ctx context.Context, targetGroupArn string) (string, error) {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	input := &elbv2.DescribeTargetGroupsInput{
		TargetGroupArns: []string{targetGroupArn},
	}

	result, err := svc.DescribeTargetGroups(ctx, input)
	if err != nil {
		return "", err
	}

	if len(result.TargetGroups) == 0 {
		return "", fmt.Errorf("cannot find target group with arn %v", targetGroupArn)
	}

	tg := result.TargetGroups[0]
	if len(tg.LoadBalancerArns) == 0 {
		return "", fmt.Errorf("target group %v has no load balancer", targetGroupArn)
	}

	return tg.LoadBalancerArns[0], nil // Only 1 LB per tg possible according to aws docs
}

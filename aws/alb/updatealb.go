package alb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"defang.io/cloudacme/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go/ptr"
)

var ErrRuleNotFound = errors.New("rule not found")

type RuleCondition struct {
	PathPattern []string
	HostHeader  []string
}

func DeleteListenerPathRule(ctx context.Context, listenerArn string, target RuleCondition) error {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	searchInput := &elbv2.DescribeRulesInput{
		ListenerArn: &listenerArn,
	}
	rulesOutput, err := svc.DescribeRules(ctx, searchInput)
	if err != nil {
		return err
	}

	ruleArn := ""
rules:
	for _, rule := range rulesOutput.Rules {
		for _, cond := range rule.Conditions {
			if cond.PathPatternConfig != nil && target.PathPattern != nil && sameStringSlicesUnordered(cond.PathPatternConfig.Values, target.PathPattern) {
				continue rules
			}
			if cond.HostHeaderConfig != nil && target.HostHeader != nil && sameStringSlicesUnordered(cond.HostHeaderConfig.Values, target.HostHeader) {
				continue rules
			}
			// Only path and host header conditions are supported for now
			if cond.SourceIpConfig != nil || cond.QueryStringConfig != nil || cond.HttpHeaderConfig != nil || cond.HttpRequestMethodConfig != nil {
				continue rules
			}
			ruleArn = *rule.RuleArn
			break rules
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

func AddListenerStaticRule(ctx context.Context, listenerArn string, ruleCond RuleCondition, value string) error {
	svc := elbv2.NewFromConfig(aws.LoadConfig())

	priority, err := GetNextAvailablePriority(ctx, listenerArn)
	if err != nil {
		return err
	}

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
				Field:             ptr.String("path-pattern"),
				PathPatternConfig: &types.PathPatternConditionConfig{Values: ruleCond.PathPattern},
			},
			{
				Field:            ptr.String("host-header"),
				HostHeaderConfig: &types.HostHeaderConditionConfig{Values: ruleCond.HostHeader},
			},
		},
		ListenerArn: &listenerArn,
		Priority:    ptr.Int32(priority),
	}

	if _, err := svc.CreateRule(ctx, input); err != nil {
		return err
	}
	return nil
}

func GetNextAvailablePriority(ctx context.Context, listenerArn string) (int32, error) {
	rules, err := GetAllRules(ctx, listenerArn)
	if err != nil {
		return 0, err
	}

	ps := make([]int, 0, len(rules))
	for _, rule := range rules {
		if rule.Priority == nil {
			continue
		}
		p, err := strconv.Atoi(*rule.Priority)
		if err != nil {
			continue
		}
		ps = append(ps, p)
	}
	ps = sort.IntSlice(ps)
	priority := 1
	for _, p := range ps {
		if priority == p {
			priority++
		} else {
			break
		}
	}
	return int32(priority), nil
}

func GetAllRules(ctx context.Context, listenerArn string) ([]types.Rule, error) {
	svc := elbv2.NewFromConfig(aws.LoadConfig())

	var rules []types.Rule
	for {
		searchInput := &elbv2.DescribeRulesInput{
			ListenerArn: &listenerArn,
			PageSize:    ptr.Int32(400),
		}

		searchOuputput, err := svc.DescribeRules(ctx, searchInput)
		if err != nil {
			return nil, err
		}
		rules = append(rules, searchOuputput.Rules...)

		if searchOuputput.NextMarker == nil {
			return rules, nil
		}
		searchInput.Marker = searchOuputput.NextMarker
	}
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

func sameStringSlicesUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	diff := make(map[string]int)
	for _, s := range a {
		diff[s]++
	}
	for _, s := range b {
		diff[s]--
	}
	for _, v := range diff {
		if v != 0 {
			return false
		}
	}
	return true
}

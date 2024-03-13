package alb

import (
	"context"
	"errors"
	"log"

	"defang.io/acme/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go/ptr"
)

const AlbArn = "arn:aws:elasticloadbalancing:us-west-2:381492210770:loadbalancer/app/Defang-acmetest-beta-alb/6d3dcd8ea647aba8"

// func main() {
//
// 	ctx := context.Background()
//
// 	listener := getHttpListener(ctx, AlbArn)
// 	if listener == nil {
// 		log.Fatalf("unable to find HTTP listener")
// 	}
//
// 	log.Printf("Listener ARN: %s", *listener.ListenerArn)
//
// 	addListenerStaticRule(ctx, *listener.ListenerArn, "/test", "Hello, World!")
// 	time.Sleep(15 * time.Second)
// 	deleteListenerStaticRule(ctx, *listener.ListenerArn, "/test")
// }

func DeleteListenerStaticRule(ctx context.Context, listenerArn, path string) error {
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
		if rule.Conditions[0].PathPatternConfig != nil && rule.Conditions[0].PathPatternConfig.Values[0] == path {
			ruleArn = *rule.RuleArn
			break
		}
	}
	if ruleArn == "" {
		return errors.New("rule not found")
	}

	input := &elbv2.DeleteRuleInput{
		RuleArn: &ruleArn,
	}

	if _, err := svc.DeleteRule(ctx, input); err != nil {
		log.Fatalf("unable to delete rule, %v", err)
	}
	return nil
}

func AddListenerStaticRule(ctx context.Context, listenerArn, path, value string) error {
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
		Priority:    ptr.Int32(1),
	}

	_, err := svc.CreateRule(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

func GetHttpListener(ctx context.Context, albArn string) (*types.Listener, error) {
	svc := elbv2.NewFromConfig(aws.LoadConfig())
	input := &elbv2.DescribeListenersInput{
		LoadBalancerArn: &albArn,
	}

	result, err := svc.DescribeListeners(ctx, input)
	if err != nil {
		return nil, err
	}

	for _, listener := range result.Listeners {
		if listener.Protocol == types.ProtocolEnumHttp && listener.Port != nil && *listener.Port == 80 {
			return &listener, nil
		}
	}
	return nil, errors.New("Listener not found")
}

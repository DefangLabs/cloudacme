package main

import (
	"context"
	"fmt"

	"defang.io/cloudacme/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

var listenerArn = "arn:aws:elasticloadbalancing:us-west-2:381492210770:listener/app/Defang-dayifu2-beta-alb/6f1d3e4bf5cbac4b/84ccc1071870455c"
var path = "/"

func main() {
	ctx := context.Background()

	svc := elbv2.NewFromConfig(aws.LoadConfig())
	searchInput := &elbv2.DescribeRulesInput{
		ListenerArn: &listenerArn,
	}
	rulesOutput, err := svc.DescribeRules(ctx, searchInput)
	if err != nil {
		panic(err)
	}

	for _, rule := range rulesOutput.Rules {
		fmt.Printf("RuleArn: %v\n", *rule.RuleArn)
		for _, condition := range rule.Conditions {
			fmt.Printf("Condition Type: %v\n", *condition.Field)
			if condition.PathPatternConfig != nil {
				fmt.Printf("\tPathPatternConfig: %v\n", condition.PathPatternConfig.Values)
			}
			if condition.HostHeaderConfig != nil {
				fmt.Printf("\tHostHeaderConfig: %v\n", condition.HostHeaderConfig.Values)
			}
			if condition.HttpHeaderConfig != nil {
				fmt.Printf("\tHttpHeaderConfig: %v\n", *condition.HttpHeaderConfig.HttpHeaderName)
			}
			if condition.HttpRequestMethodConfig != nil {
				fmt.Printf("\tHttpRequestMethodConfig: %v\n", condition.HttpRequestMethodConfig.Values)
			}
			if condition.QueryStringConfig != nil {
				fmt.Printf("\tQueryStringConfig: %v\n", condition.QueryStringConfig.Values)
			}
			if condition.SourceIpConfig != nil {
				fmt.Printf("\tSourceIpConfig: %v\n", condition.SourceIpConfig.Values)
			}
			fmt.Printf("Values: %v\n", condition.Values)
		}
	}
}

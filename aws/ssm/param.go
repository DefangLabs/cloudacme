package ssm

import (
	"context"

	"defang.io/cloudacme/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go/ptr"
)

func GetParameter(ctx context.Context, name string) (string, error) {
	client := ssm.NewFromConfig(aws.LoadConfig())
	input := &ssm.GetParameterInput{
		Name:           &name,
		WithDecryption: ptr.Bool(true),
	}
	result, err := client.GetParameter(ctx, input)
	if err != nil {
		return "", err
	}
	return *result.Parameter.Value, nil
}

func PutParameter(ctx context.Context, name string, value string) error {
	client := ssm.NewFromConfig(aws.LoadConfig())
	input := &ssm.PutParameterInput{
		Name:      &name,
		Value:     &value,
		Type:      types.ParameterTypeSecureString,
		Overwrite: ptr.Bool(true),
	}
	_, err := client.PutParameter(ctx, input)
	return err
}

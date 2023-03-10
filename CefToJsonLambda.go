package main

import (
	"encoding/json"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type CefToJsonLambda struct {
	pulumi.ResourceState
}

type CefToJsonLambdaArgs struct {
	sourceBucketId pulumi.IDOutput
	handler        string
	pathToArchive  string
}

func NewCefToJsonLambda(ctx *pulumi.Context, name string, args *CefToJsonLambdaArgs, opts ...pulumi.ResourceOption) (*CefToJsonLambda, error) {
	comp := &CefToJsonLambda{}

	assumePolicy := Policy{
		Version: "2012-10-17",
		Statements: []Statement{
			{
				Action: []string{"sts:AssumeRole"},
				Principal: &map[string]string{
					"Service": "lambda.amazonaws.com",
				},
				Effect: "Allow",
			},
		},
	}

	assumeJson, err := json.Marshal(assumePolicy)
	if err != nil {
		return nil, err
	}

	lambdaRole, err := iam.NewRole(ctx, "lambda", &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(assumeJson),
	}, opts...)

	if err != nil {
		return nil, err
	}

	logPolicy, err := json.Marshal(Policy{
		Version: "2012-10-17",
		Statements: []Statement{
			{
				Effect: "Allow",
				Action: []string{
					"logs:CreateLogGroup",
					"logs:CreateLogStream",
					"logs:PutLogEvents",
				},
				Resource: &[]string{"arn:aws:logs:*:*:*"},
			},
		},
	})

	if err != nil {
		return nil, err
	}

	_, err = iam.NewRolePolicy(ctx, "lambda-rp", &iam.RolePolicyArgs{
		Role:   lambdaRole.Name,
		Policy: pulumi.String(logPolicy),
	}, opts...)

	if err != nil {
		return nil, err
	}

	lambdaFn, err := lambda.NewFunction(ctx, "cef-to-json", &lambda.FunctionArgs{
		Role:    lambdaRole.Arn,
		Runtime: pulumi.String("1.x"),
		Handler: pulumi.String(args.handler),
		Code:    pulumi.NewFileArchive(args.pathToArchive),
	})

	if err != nil {
		return nil, err
	}

	perm, err := lambda.NewPermission(ctx, "cef-invoke", &lambda.PermissionArgs{
		Action:    pulumi.String("lambda:InvokeFunction"),
		Function:  lambdaFn.Arn,
		Principal: pulumi.String("s3.amazonaws.com"),
		SourceArn: args.sourceBucketId,
	})

	if err != nil {
		return nil, err
	}

	_, err = s3.NewBucketNotification(ctx, "cef-notification", &s3.BucketNotificationArgs{
		Bucket: args.sourceBucketId,
		LambdaFunctions: s3.BucketNotificationLambdaFunctionArray{
			&s3.BucketNotificationLambdaFunctionArgs{
				LambdaFunctionArn: lambdaFn.Arn,
				Events:            pulumi.StringArray{pulumi.String("s3:ObjectCreated:*")},
				FilterSuffix:      pulumi.String(".ceff"),
			},
		},
	}, pulumi.DependsOn([]pulumi.Resource{perm}))

	if err != nil {
		return nil, err
	}

	err = ctx.RegisterComponentResource("pkg:index:CefToJsonLambda", name, comp, opts...)
	if err != nil {
		return nil, err
	}

	return comp, nil
}

package main

import (
	"encoding/json"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type CefToJsonLambda struct {
	pulumi.ResourceState

	LambdaArn pulumi.StringOutput
}

type CefToJsonLambdaArgs struct {
	SourceBucketName      pulumi.StringOutput
	SourceBucketArn       pulumi.StringOutput
	DestinationBucketName pulumi.StringOutput
	DestinationBucketArn  pulumi.StringOutput
	Handler               string
	PathToArchive         string
}

func NewCefToJsonLambda(ctx *pulumi.Context, name string, args *CefToJsonLambdaArgs, opts ...pulumi.ResourceOption) (*CefToJsonLambda, error) {
	var comp CefToJsonLambda

	err := ctx.RegisterComponentResource("pkg:index:CefToJsonLambda", name, &comp, opts...)
	if err != nil {
		return nil, err
	}

	compOpts := append(opts, pulumi.Parent(&comp))

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
	}, compOpts...)

	if err != nil {
		return nil, err
	}

	roleJson := pulumi.All(args.SourceBucketArn, args.DestinationBucketArn).ApplyT(func(v []interface{}) (string, error) {
		sourceArn := v[0].(string)
		destinationArn := v[1].(string)

		policy, err := json.Marshal(Policy{
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
				{
					Effect: "Allow",
					Action: []string{
						"s3:GetObject*",
						"s3:ListBucket",
					},
					Resource: &[]string{
						sourceArn,
						fmt.Sprintf("%s/*", sourceArn),
					},
				},
				{
					Effect: "Allow",
					Action: []string{
						"s3:PutObject",
						"s3:PutObjectAcl",
						"s3:AbortMultipartUpload",
						"s3:ListBucket",
						"s3:GetObject",
					},
					Resource: &[]string{
						destinationArn,
						fmt.Sprintf("%s/*", destinationArn),
					},
				},
			},
		})

		if err != nil {
			return "", err
		}

		return string(policy), nil
	}).(pulumi.StringOutput)

	_, err = iam.NewRolePolicy(ctx, "func-rp", &iam.RolePolicyArgs{
		Role:   lambdaRole.Name,
		Policy: roleJson,
	}, compOpts...)

	if err != nil {
		return nil, err
	}

	lambdaFn, err := lambda.NewFunction(ctx, "cef-to-json", &lambda.FunctionArgs{
		Role:    lambdaRole.Arn,
		Runtime: pulumi.String("go1.x"),
		Handler: pulumi.String(args.Handler),
		Code:    pulumi.NewFileArchive(args.PathToArchive),
		Environment: lambda.FunctionEnvironmentArgs{
			Variables: pulumi.StringMap{
				"DEST_BUCKET": args.DestinationBucketName,
			},
		},
	}, compOpts...)

	if err != nil {
		return nil, err
	}

	perm, err := lambda.NewPermission(ctx, "cef-invoke", &lambda.PermissionArgs{
		Action:    pulumi.String("lambda:InvokeFunction"),
		Function:  lambdaFn.Arn,
		Principal: pulumi.String("s3.amazonaws.com"),
		SourceArn: args.SourceBucketArn,
	}, compOpts...)

	if err != nil {
		return nil, err
	}

	permOpts := append(compOpts, pulumi.DependsOn([]pulumi.Resource{perm}))
	_, err = s3.NewBucketNotification(ctx, "cef-notification", &s3.BucketNotificationArgs{
		Bucket: args.SourceBucketName,
		LambdaFunctions: s3.BucketNotificationLambdaFunctionArray{
			&s3.BucketNotificationLambdaFunctionArgs{
				LambdaFunctionArn: lambdaFn.Arn,
				Events:            pulumi.StringArray{pulumi.String("s3:ObjectCreated:*")},
				FilterSuffix:      pulumi.String(".ceff"),
			},
		},
	}, permOpts...)

	if err != nil {
		return nil, err
	}

	comp.LambdaArn = lambdaFn.Arn

	return &comp, nil
}

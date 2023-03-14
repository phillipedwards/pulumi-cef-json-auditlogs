package main

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

type Statement struct {
	Action    []string                `json:"Action"`
	Resource  *[]string               `json:"Resource,omitempty"`
	Effect    string                  `json:"Effect"`
	Principal *map[string]string      `json:"Principal,omitempty"`
	Condition *map[string]interface{} `json:"Condition,omitempty"`
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		awsCfg := config.New(ctx, "aws")
		awsProvider, err := aws.NewProvider(ctx, "aws-provider", &aws.ProviderArgs{
			Profile: pulumi.String(awsCfg.Require("profile")),
			Region:  aws.Region(awsCfg.Require("region")),
		})

		// providers := pulumi.ProviderMap(
		// 	map[string]pulumi.ProviderResource{
		// 		"aws": awsProvider,
		// 	},
		// )

		if err != nil {
			return err
		}

		cfg := config.New(ctx, "")
		logPath := cfg.Get("log-path")
		if logPath == "" {
			logPath = "pulumi-audit-logs"
		}

		accountId := cfg.Get("pulumi-source-account-id")
		if accountId == "" {
			accountId = "058607598222"
		}

		// // it's possibly to BYOB that is already receiving Pulumi Audit Logs
		bucketName := cfg.Get("cef-bucket-name")
		var cefBucketName pulumi.StringOutput
		var cefBucketArn pulumi.StringOutput
		if bucketName != "" {
			cefBucketName = pulumi.String(bucketName).ToStringOutput()
			cefBucketArn = pulumi.String(fmt.Sprintf("arn:aws:s3:::%s", bucketName)).ToStringOutput()
		} else {
			cefBucket, err := s3.NewBucketV2(ctx, "cef-audit-logs", &s3.BucketV2Args{
				ForceDestroy: pulumi.Bool(true),
			}, pulumi.Provider(awsProvider))

			if err != nil {
				return err
			}

			cefRole, err := NewPulumiAuditLogBucket(ctx, "cef-bucket", &PulumiAuditLogBucketArgs{
				LogPath:      logPath,
				AccountId:    accountId,
				CefBucketArn: cefBucket.Arn,
			}, pulumi.Provider(awsProvider))

			if err != nil {
				return err
			}

			cefBucketName = cefBucket.Bucket
			cefBucketArn = cefBucket.Arn

			ctx.Export("cef-role-arn", cefRole.RoleArn)
		}

		jsonBucket, err := s3.NewBucketV2(ctx, "json-audit-logs", &s3.BucketV2Args{
			ForceDestroy: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return err
		}

		converterLambda, err := NewCefToJsonLambda(ctx, "cef-json-conv", &CefToJsonLambdaArgs{
			SourceBucketName:      cefBucketName,
			SourceBucketArn:       cefBucketArn,
			DestinationBucketName: jsonBucket.Bucket,
			DestinationBucketArn:  jsonBucket.Arn,
			PathToArchive:         "./handler/handler.zip",
			Handler:               "handler",
		}, pulumi.Provider(awsProvider))

		if err != nil {
			return err
		}

		ctx.Export("json-bucket-arn", jsonBucket.Arn)
		ctx.Export("cef-bucket-arn", cefBucketArn)
		ctx.Export("converter-lambda", converterLambda.LambdaArn)
		ctx.Export("aws-logs-path", pulumi.String(logPath))
		return nil
	})
}

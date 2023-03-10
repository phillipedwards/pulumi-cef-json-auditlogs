package main

import (
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
		cfg := config.New(ctx, "")
		accountId := cfg.Require("aws-account-id")
		logPath := cfg.Get("log-path")
		if logPath == "" {
			logPath = "pulumi-audit-logs"
		}

		jsonBucket, err := s3.NewBucketV2(ctx, "pulumi-json-export-bucket", &s3.BucketV2Args{}, pulumi.Protect(true))
		if err != nil {
			return err
		}

		cefBucket, err := NewPulumiAuditLogBucket(ctx, "cef-bucket", &PulumiAuditLogBucketArgs{
			LogPath:   logPath,
			AccountId: accountId,
		})

		if err != nil {
			return err
		}

		ctx.Export("cef", cefBucket.CefBucketId)
		ctx.Export("json", jsonBucket.ID())
		ctx.Export("exporter-role", cefBucket.RoleArn)
		return nil
	})
}
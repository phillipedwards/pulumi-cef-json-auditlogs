package main

import (
	"encoding/json"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type PulumiAuditLogBucket struct {
	pulumi.ResourceState

	RoleArn pulumi.StringOutput
}

type PulumiAuditLogBucketArgs struct {
	AccountId    string
	LogPath      string
	CefBucketArn pulumi.StringOutput
}

func NewPulumiAuditLogBucket(ctx *pulumi.Context, name string, args *PulumiAuditLogBucketArgs, opts ...pulumi.ResourceOption) (*PulumiAuditLogBucket, error) {
	var comp PulumiAuditLogBucket

	err := ctx.RegisterComponentResource("pkg:index:PulumiAuditLogBucket", name, &comp, opts...)
	if err != nil {
		return nil, err
	}

	parentOpts := append(opts, pulumi.Parent(&comp))

	assumeRolePolicy, err := json.Marshal(&Policy{
		Version: "2012-10-17",
		Statements: []Statement{
			{
				Action: []string{"sts:AssumeRole"},
				Effect: "Allow",
				Principal: &map[string]string{
					"AWS": fmt.Sprintf("arn:aws:iam::%s:root", args.AccountId),
				},
				Condition: &map[string]interface{}{
					"StringEquals": map[string]string{
						"sts:ExternalId": "demo",
					},
				},
			},
		},
	})

	if err != nil {
		return nil, err
	}

	ctx.Log.Debug(fmt.Sprintf("assume-role-policy::%v", string(assumeRolePolicy)), nil)

	role, err := iam.NewRole(ctx, fmt.Sprintf("cef-role-%s", name), &iam.RoleArgs{
		Description:      pulumi.String("Role for Pulumi to Export Audit Logs to S3"),
		AssumeRolePolicy: pulumi.String(assumeRolePolicy),
	}, parentOpts...)

	if err != nil {
		return nil, err
	}

	roleJson := args.CefBucketArn.ApplyT(func(s string) (string, error) {
		policy, err := json.Marshal(&Policy{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Action:   []string{"s3:GetBucketLocation"},
					Effect:   "Allow",
					Resource: &[]string{s},
				},
				{
					Action: []string{
						"s3:PutObject",
						"s3:PutObjectAcl",
						"s3:AbortMultipartUpload",
					},
					Effect: "Allow",
					Resource: &[]string{
						fmt.Sprintf("%s/%s/", s, args.LogPath),
						fmt.Sprintf("%s/%s/*", s, args.LogPath),
					},
				},
			},
		})

		if err != nil {
			return "", err
		}

		ctx.Log.Debug(fmt.Sprintf("iam-role-policy::%v", policy), nil)

		return string(policy), nil
	}).(pulumi.StringOutput)

	if err != nil {
		return nil, err
	}

	_, err = iam.NewRolePolicy(ctx, fmt.Sprintf("policy-%s", name), &iam.RolePolicyArgs{
		Role:   role.Name,
		Policy: roleJson,
	}, parentOpts...)

	if err != nil {
		return nil, err
	}

	comp.RoleArn = role.Arn

	return &comp, nil
}

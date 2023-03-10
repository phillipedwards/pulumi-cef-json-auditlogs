package main

import (
	"encoding/json"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type PulumiAuditLogBucket struct {
	pulumi.ResourceState

	CefBucketId pulumi.IDOutput
	RoleArn     pulumi.StringOutput
}

type PulumiAuditLogBucketArgs struct {
	AccountId string
	LogPath   string
}

func NewPulumiAuditLogBucket(ctx *pulumi.Context, name string, args *PulumiAuditLogBucketArgs, opts ...pulumi.ResourceOption) (*PulumiAuditLogBucket, error) {
	comp := &PulumiAuditLogBucket{}

	cefBucket, err := s3.NewBucketV2(ctx, "pulumi-cef-export-bucket", &s3.BucketV2Args{}, pulumi.Protect(true))
	if err != nil {
		return nil, err
	}

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

	role, err := iam.NewRole(ctx, "cef-role", &iam.RoleArgs{
		Description:      pulumi.String("Role for Pulumi to Export Audit Logs to S3"),
		NamePrefix:       pulumi.String("pulumi-export-s3"),
		AssumeRolePolicy: pulumi.String(assumeRolePolicy),
	})

	if err != nil {
		return nil, err
	}

	roleJson := cefBucket.Bucket.ApplyT(func(s string) (string, error) {
		policy, err := json.Marshal(&Policy{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Action:   []string{"s3:GetBucketLocadtion"},
					Effect:   "Allow",
					Resource: &[]string{fmt.Sprintf("arn:aws:s3:::%s", s)},
				},
				{
					Action: []string{
						"s3:PutObject",
						"s3:PutObjectAcl",
						"s3:AbortMultipartUpload"},
					Effect: "Allow",
					Resource: &[]string{
						fmt.Sprintf("arn:aws:s3:::%s/%s/", s, args.LogPath),
						fmt.Sprintf("arn:aws:s3:::%s/%s/*", s, args.LogPath),
					},
				},
			},
		})

		if err != nil {
			return "", err
		}

		return string(policy), nil
	}).(pulumi.StringOutput)

	if err != nil {
		return nil, err
	}

	_, err = iam.NewRolePolicy(ctx, "cef-policy", &iam.RolePolicyArgs{
		Role:   role.Name,
		Policy: roleJson,
	})

	if err != nil {
		return nil, err
	}

	err = ctx.RegisterComponentResource("pkg:index:PulumiAuditLogBucket", name, comp, opts...)
	if err != nil {
		return nil, err
	}

	comp.CefBucketId = cefBucket.ID()
	comp.RoleArn = role.Arn

	return comp, nil
}

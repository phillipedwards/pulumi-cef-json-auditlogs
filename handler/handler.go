package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	//"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/smithy-go/ptr"
)

type AuditEvent struct {
	Timestamp      string            `json:"timestamp"`
	Host           string            `json:"host"`
	Data           map[string]string `json:"data"`
	Vendor         string            `json:"vendor"`
	Product        string            `json:"product"`
	ProductVersion string            `json:"productVersion"`
	EventClassID   string            `json:"eventClassId"`
	EventName      string            `json:"eventName"`
	EventSeverity  string            `json:"eventSeverity"`
	Raw            string            `json:"raw"`
	Version        string            `json:"version"`
}

func (e AuditEvent) ToJson() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

var (
	s3Client          *s3.Client
	destinationBucket string
)

func init() {
	region := os.Getenv("AWS_REGION")
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		fmt.Printf("error encountered while creating config %s \n", err.Error())
		return
	}

	s3Client = s3.NewFromConfig(cfg)
	destinationBucket = os.Getenv("DEST_BUCKET")
}

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, s3Event events.S3Event) (string, error) {

	fmt.Println("processing s3 event notifications")

	// iterate over the objects we received notifications for
	for _, record := range s3Event.Records {
		s3Record := record.S3
		fmt.Printf("[%s - %s] Bucket = %s, Key = %s \n", record.EventSource, record.EventTime, s3Record.Bucket.Name, s3Record.Object.Key)

		// read in object from s3 bucket
		obj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &s3Record.Bucket.Name,
			Key:    &s3Record.Object.Key,
		})

		if err != nil {
			return "", err
		}

		buf := new(bytes.Buffer)
		numBytes, err := buf.ReadFrom(obj.Body)
		if err != nil {
			fmt.Println(err)
			return "", err
		}

		fmt.Printf("read %d bytes from s3 \n", numBytes)

		obj.Body.Close()

		// possible to have more than one line so split on newline
		// each line could have multiple files
		content := splitToArray(buf.String())

		// read each line and parse string to event struct
		events := parseEventsfromContent(content)

		// to json for each record present and write to a file in the same name to output bucket
		fName := getJsonFileNameFromObject(s3Record.Object.Key)
		writeToBucket(ctx, events, fName)

		fmt.Printf("successfully wrote %s to bucket %s", fName, destinationBucket)
	}
	return "", nil
}

func splitToArray(raw string) []string {
	return strings.Split(raw, "\n")
}

func getJsonFileNameFromObject(ceffName string) string {
	split := strings.Split(ceffName, ".")
	return fmt.Sprintf("%s.json", split[0])
}

func parseEventsfromContent(raw []string) []AuditEvent {
	events := make([]AuditEvent, len(raw))
	for _, r := range raw {
		events = append(events, parseCefEvent(r))
	}

	return events
}

// Pulumi Service Audit Event follows:
//  Timestamp host CEF:version|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassID|Name|severity|key=value
func parseCefEvent(raw string) AuditEvent {
	// ex Feb 14 14:53:01 api.pulumi.com CEF:0|Pulumi|Pulumi Service|1.0|User Login|User "tushar-pulumi-corp" logged into the Pulumi Console.|0|authenticationFailure=false dvchost=api.pulumi.com orgID=bbdf1c46-4a7b-497c-8b3d-0acf8a55e505 requireOrgAdmin=false requireStackAdmin=false rt=1676386381000 src=99.159.29.103 suser=tushar-pulumi-corp tokenID= tokenName= userID=b557a719-8291-4cd3-93e4-fa5405c0ce49

	splits := strings.Fields(raw)

	// first three members of our slice should be timestamp
	timestamp := strings.Join(splits[:3], " ")

	// 4th member is our host. eg- api.com/pulumi
	host := splits[3]

	// the remainder should be in some CEF format (see above)
	// rejoin the strings to give us a clean start
	remainder := strings.Join(splits[4:], " ")

	cefEvent := strings.Split(remainder, "|")

	// CEF:{version}
	version := strings.Split(cefEvent[0], ":")[1]
	vendor := cefEvent[1]
	product := cefEvent[2]
	productVersion := cefEvent[3]
	eventClassId := cefEvent[4]
	eventName := cefEvent[5]
	severity := cefEvent[6]
	kv := cefEvent[7]
	data := parseKv(kv)

	return AuditEvent{
		Timestamp:      timestamp,
		Host:           host,
		Raw:            raw,
		Version:        version,
		Vendor:         vendor,
		Product:        product,
		ProductVersion: productVersion,
		EventClassID:   eventClassId,
		EventName:      eventName,
		EventSeverity:  severity,
		Data:           data,
	}
}

func parseKv(raw string) map[string]string {
	// raw should be space delimited key=value pairs
	kv := strings.Fields(raw)
	m := make(map[string]string)
	for _, pair := range kv {
		// lets split the kv pair by = and build our map
		s := strings.Split(pair, "=")
		m[s[0]] = s[1]
	}

	return m
}

func writeToBucket(ctx context.Context, events []AuditEvent, key string) error {
	var sb strings.Builder
	for _, event := range events {
		j, err := event.ToJson()
		if err != nil {
			return err
		}

		sb.WriteString(fmt.Sprintf("%s\n", j))
	}

	body := strings.NewReader(sb.String())

	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &destinationBucket,
		Key:         ptr.String(key),
		ContentType: ptr.String("application/json"),
		Body:        body,
	})

	if err != nil {
		return err
	}

	return nil
}

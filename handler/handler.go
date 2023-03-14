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

var (
	s3Client          *s3.Client
	destinationBucket string
)

// marshal our audit log event to JSON after conversion
func (e AuditEvent) ToJson() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// new up the bits required across executions
// if our destination bucket (JSON bucket) is not present it's fatal
func init() {
	region := os.Getenv("AWS_REGION")
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		fmt.Printf("error encountered while creating config %s \n", err.Error())
		return
	}

	s3Client = s3.NewFromConfig(cfg)
	destinationBucket = os.Getenv("DEST_BUCKET")
	if destinationBucket == "" {
		panic("DEST_BUCKET env var must not be nil")
	}
}

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, s3Event events.S3Event) (string, error) {

	fmt.Println("processing s3 event notifications")

	// iterate over the objects we received notifications for this given notification
	// it's possible to receive multiples
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

		if numBytes <= 0 {
			fmt.Printf("audit log file %s is empty. no action processed\n", s3Record.Object.Key)
			continue
		}

		// to json for each record present and write to a file in the same name to output bucket
		fName := getJsonFileNameFromObject(s3Record.Object.Key)

		// query our destination bucket to see if an object with the above key already exists
		_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: ptr.String(destinationBucket),
			Key:    &fName,
		})

		// if our key does not exist on the destination bucket, we'd expect a 404 error
		// this should stop replay issues
		if err == nil {
			fmt.Printf("possibly duplicate notification %s. ignoring request", fName)
			continue
		}

		// possible to have more than one line so split on newline
		// each line could have multiple files
		content := splitToArray(buf.String())

		// read each line and parse string to event struct
		events := parseEventsfromContent(content)

		writeToBucket(ctx, events, fName)

		fmt.Printf("successfully wrote %s to bucket %s", fName, destinationBucket)
	}
	return "", nil
}

// pulumi audit logs come in \n delimited files
func splitToArray(raw string) []string {
	return strings.Split(raw, "\n")
}

// split the filename out from the extension to be used for writing our new json file
func getJsonFileNameFromObject(ceffName string) string {
	split := strings.Split(ceffName, ".")
	return fmt.Sprintf("%s.json", split[0])
}

// main parsing function which turns raw ceff strings into a struct
func parseEventsfromContent(raw []string) []AuditEvent {
	var events []AuditEvent
	for _, r := range raw {
		if r != "" {
			events = append(events, parseCefEvent(r))
		}
	}

	return events
}

// goal is to take a raw ceff string and convert it to our struct AuditEvent
// we could also rip this straight into JSON, but I like strongly typed stuff
func parseCefEvent(raw string) AuditEvent {
	// ex Feb 14 14:53:01 api.pulumi.com CEF:0|Pulumi|Pulumi Service|1.0|User Login|User "tushar-pulumi-corp" logged into the Pulumi Console.|0|authenticationFailure=false dvchost=api.pulumi.com orgID=bbdf1c46-4a7b-497c-8b3d-0acf8a55e505 requireOrgAdmin=false requireStackAdmin=false rt=1676386381000 src=99.159.29.103 suser=tushar-pulumi-corp tokenID= tokenName= userID=b557a719-8291-4cd3-93e4-fa5405c0ce49

	fmt.Printf("Input: %s\n", raw)
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

// part of the ceff payload is a key=value component which contains arbitrary data associated with the type of event
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

// take the array of AuditEvents, marshal it to JSON, and write it to the destination bucket
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

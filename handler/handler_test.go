package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setEnv() {
	os.Setenv("DEST_BUCKET", "SOME_BUCKET")
}

// Timestamp host CEF:version|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassID|Name|severity|key=value
func TestParseCefEvent(t *testing.T) {
	setEnv()

	input := "Feb 14 14:53:01 api.pulumi.com CEF:0|Pulumi|Pulumi Service|1.0|User Login|User \"tushar-pulumi-corp\" logged into the Pulumi Console.|0|authenticationFailure=false dvchost=api.pulumi.com orgID=bbdf1c46-4a7b-497c-8b3d-0acf8a55e505 requireOrgAdmin=false requireStackAdmin=false rt=1676386381000 src=99.159.29.103 suser=tushar-pulumi-corp tokenID= tokenName= userID=b557a719-8291-4cd3-93e4-fa5405c0ce49"
	parsed := parseCefEvent(input)

	assert.Equal(t, "Feb 14 14:53:01", parsed.Timestamp)
	assert.Equal(t, "api.pulumi.com", parsed.Host)
	assert.Equal(t, "0", parsed.Version)
	assert.Equal(t, "Pulumi", parsed.Vendor)
	assert.Equal(t, "Pulumi Service", parsed.Product)
	assert.Equal(t, "1.0", parsed.ProductVersion)
	assert.Equal(t, "User Login", parsed.EventClassID)
	assert.Equal(t, "User \"tushar-pulumi-corp\" logged into the Pulumi Console.", parsed.EventName)
	assert.Equal(t, "0", parsed.EventSeverity)

	m := map[string]string{
		"authenticationFailure": "false",
		"dvchost":               "api.pulumi.com",
		"orgID":                 "bbdf1c46-4a7b-497c-8b3d-0acf8a55e505",
		"requireOrgAdmin":       "false",
		"requireStackAdmin":     "false",
		"rt":                    "1676386381000",
		"src":                   "99.159.29.103",
		"suser":                 "tushar-pulumi-corp",
		"tokenID":               "",
		"tokenName":             "",
		"userID":                "b557a719-8291-4cd3-93e4-fa5405c0ce49",
	}
	for k, v := range parsed.Data {
		assert.Equal(t, m[k], v, fmt.Sprintf("error matching value %s. %s", k, v))
	}
}

func TestGetJsonFileNameFromCeffName(t *testing.T) {
	setEnv()

	name := "2023-02-14_14"
	input := fmt.Sprintf("%s.ceff", name)
	actual := getJsonFileNameFromObject(input)
	assert.Equal(t, fmt.Sprintf("%s.json", name), actual)
}

func TestSplitRawToArray(t *testing.T) {
	setEnv()

	input := `Feb 14 14:53:01 api.pulumi.com CEF:0|Pulumi|Pulumi Service|1.0|User Login|User "tushar-pulumi-corp" logged into the Pulumi Console.|0|authenticationFailure=false dvchost=api.pulumi.com orgID=bbdf1c46-4a7b-497c-8b3d-0acf8a55e505 requireOrgAdmin=false requireStackAdmin=false rt=1676386381000 src=99.159.29.103 suser=tushar-pulumi-corp tokenID= tokenName= userID=b557a719-8291-4cd3-93e4-fa5405c0ce49 
	Feb 14 14:51:47 api.pulumi.com CEF:0|Pulumi|Pulumi Service|1.0|User Login|User "shaht" logged into the Pulumi Console.|0|authenticationFailure=false dvchost=api.pulumi.com orgID=bbdf1c46-4a7b-497c-8b3d-0acf8a55e505 requireOrgAdmin=false requireStackAdmin=false rt=1676386307000 src=99.159.29.103 suser=shaht tokenID= tokenName= userID=fb4716e8-dd2b-4133-93d7-f2d0edd3b8fb`
	actual := splitToArray(input)
	assert.Equal(t, 2, len(actual))
}

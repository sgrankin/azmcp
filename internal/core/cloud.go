package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string        { return e.Message }
func Fail(code, message string) error { return &Error{Code: code, Message: message} }

type Cloud string

const (
	Commercial               Cloud = "AzureCloud"
	Government               Cloud = "AzureUSGovernment"
	PolicyVersion                  = "v1-observability-2"
	PolicyHash                     = "sha256:120f3e489269e7dd720808354fdb8ccf8862e7d3f726e3d7179e1b452a20a0ed"
	SubscriptionsAPIVersion        = "2020-01-01"
	ProvidersAPIVersion            = "2021-04-01"
	GraphAPIVersion                = "2022-10-01"
	MetricsAPIVersion              = "2023-10-01"
	LogsAPIVersion                 = "v1"
	ArtifactsWriteCapability       = "artifacts.write"
)

func ParseCloud(value string) (Cloud, error) {
	c := Cloud(value)
	if c != Commercial && c != Government {
		return "", Fail("invalid_request", "unsupported Azure cloud")
	}
	return c, nil
}
func (c *Cloud) UnmarshalJSON(raw []byte) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	parsed, err := ParseCloud(value)
	if err == nil {
		*c = parsed
	}
	return err
}

type AuthenticationManifest struct {
	Authority string   `json:"authority"`
	Audiences []string `json:"audiences"`
}
type EndpointSuffixes struct {
	Management string `json:"management"`
	KeyVault   string `json:"keyVault"`
	SQL        string `json:"sql"`
	Storage    string `json:"storage"`
}
type DataPlaneEndpoints struct {
	ResourceGraph     string `json:"resourceGraph"`
	Metrics           string `json:"metrics"`
	LogsQuery         string `json:"logsQuery"`
	LogsTokenResource string `json:"logsTokenResource"`
}
type CloudManifest struct {
	Cloud           Cloud                  `json:"cloud"`
	MetadataURL     string                 `json:"metadataUrl"`
	ResourceManager string                 `json:"resourceManager"`
	ActiveDirectory string                 `json:"activeDirectory"`
	Authentication  AuthenticationManifest `json:"authentication"`
	Suffixes        EndpointSuffixes       `json:"suffixes"`
	DataPlane       DataPlaneEndpoints     `json:"dataPlane"`
}

func (c Cloud) Manifest() CloudManifest {
	switch c {
	case Commercial:
		return CloudManifest{c, "https://management.azure.com/metadata/endpoints?api-version=2020-01-01", "https://management.azure.com/", "https://login.microsoftonline.com/", AuthenticationManifest{"https://login.microsoftonline.com/", []string{"https://management.azure.com/", "https://metrics.monitor.azure.com/", "https://api.loganalytics.io"}}, EndpointSuffixes{"management.azure.com", "vault.azure.net", "database.windows.net", "blob.core.windows.net"}, DataPlaneEndpoints{"https://management.azure.com/providers/Microsoft.ResourceGraph/resources", "metrics.monitor.azure.com", "https://api.loganalytics.azure.com/", "https://api.loganalytics.io"}}
	case Government:
		return CloudManifest{c, "https://management.usgovcloudapi.net/metadata/endpoints?api-version=2020-01-01", "https://management.usgovcloudapi.net/", "https://login.microsoftonline.us/", AuthenticationManifest{"https://login.microsoftonline.us/", []string{"https://management.usgovcloudapi.net/", "https://metrics.monitor.azure.us/", "https://api.loganalytics.us"}}, EndpointSuffixes{"management.usgovcloudapi.net", "vault.usgovcloudapi.net", "database.usgovcloudapi.net", "blob.core.usgovcloudapi.net"}, DataPlaneEndpoints{"https://management.usgovcloudapi.net/providers/Microsoft.ResourceGraph/resources", "metrics.monitor.azure.us", "https://api.loganalytics.us/", "https://api.loganalytics.us"}}
	default:
		panic("invalid core Cloud")
	}
}
func (c Cloud) Audience(purpose string) string {
	m := c.Manifest()
	switch purpose {
	case "metricsBatch":
		return m.Authentication.Audiences[1]
	case "logsQuery":
		return m.DataPlane.LogsTokenResource
	default:
		return m.ResourceManager
	}
}
func NormalizeID(value string) (string, error) {
	if len(value) != 36 {
		return "", Fail("invalid_request", "expected a canonical UUID")
	}
	for i, b := range []byte(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return "", Fail("invalid_request", "expected a canonical UUID")
			}
		} else if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			return "", Fail("invalid_request", "expected a canonical UUID")
		}
	}
	return strings.ToLower(value), nil
}
func validID(value string) bool                     { _, err := NormalizeID(value); return err == nil }
func detail(code, format string, args ...any) error { return Fail(code, fmt.Sprintf(format, args...)) }
func EqualFoldASCII(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range len(left) {
		a, b := left[i], right[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
func lowerASCII(value string) string {
	raw := []byte(value)
	for i, b := range raw {
		if b >= 'A' && b <= 'Z' {
			raw[i] = b + 'a' - 'A'
		}
	}
	return string(raw)
}

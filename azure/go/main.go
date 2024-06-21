package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	"github.com/fermyon/spin/sdk/go/v2/variables"
)

// SharedKeyCredential contains an account's name and its primary or secondary key.
type SharedKeyCredential struct {
	accountName string
	accountKey  []byte
}

// NewSharedKeyCredential creates an immutable SharedKeyCredential containing the
// storage account's name and either its primary or secondary key.
func NewSharedKeyCredential(accountName string, accountKey string) (*SharedKeyCredential, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return nil, fmt.Errorf("Decode account key: %w", err)
	}
	return &SharedKeyCredential{accountName: accountName, accountKey: decodedKey}, nil
}

// ComputeHMACSHA256 generates a hash signature for an HTTP request or for a SAS.
func (c *SharedKeyCredential) ComputeHMACSHA256(message string) (string, error) {
	h := hmac.New(sha256.New, c.accountKey)
	_, err := h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), err
}

func (c *SharedKeyCredential) buildStringToSign(req *http.Request) (string, error) {
	headers := req.Header
	contentLength := getHeader("Content-Length", headers)
	if contentLength == "0" {
		contentLength = ""
	}

	canonicalizedResource, err := c.buildCanonicalizedResource(req.URL)
	if err != nil {
		return "", err
	}

	stringToSign := strings.Join([]string{
		req.Method,
		getHeader("Content-Encoding", headers),
		getHeader("Content-Language", headers),
		contentLength,
		getHeader("Content-MD5", headers),
		getHeader("Content-Type", headers),
		"", // Empty date because x-ms-date is expected
		getHeader("If-Modified-Since", headers),
		getHeader("If-Match", headers),
		getHeader("If-None-Match", headers),
		getHeader("If-Unmodified-Since", headers),
		getHeader("Range", headers),
		c.buildCanonicalizedHeader(headers),
		canonicalizedResource,
	}, "\n")
	return stringToSign, nil
}

func getHeader(key string, headers http.Header) string {
	if headers == nil {
		return ""
	}
	if v, ok := headers[key]; ok {
		if len(v) > 0 {
			return v[0]
		}
	}

	return ""
}

func (c *SharedKeyCredential) buildCanonicalizedHeader(headers http.Header) string {
	cm := map[string][]string{}
	for k, v := range headers {
		headerName := strings.TrimSpace(strings.ToLower(k))
		if strings.HasPrefix(headerName, "x-ms-") {
			cm[headerName] = v // NOTE: the value must not have any whitespace around it.
		}
	}
	if len(cm) == 0 {
		return ""
	}

	keys := make([]string, 0, len(cm))
	for key := range cm {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ch := bytes.NewBufferString("")
	for i, key := range keys {
		if i > 0 {
			ch.WriteRune('\n')
		}
		ch.WriteString(key)
		ch.WriteRune(':')
		ch.WriteString(strings.Join(cm[key], ","))
	}
	return ch.String()
}

func (c *SharedKeyCredential) buildCanonicalizedResource(u *url.URL) (string, error) {
	cr := bytes.NewBufferString("/")
	cr.WriteString(c.accountName)

	if len(u.Path) > 0 {
		cr.WriteString(u.EscapedPath())
	} else {
		cr.WriteString("/")
	}

	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("Failed to parse query params: %w", err)
	}

	if len(params) > 0 {
		var paramNames []string
		for paramName := range params {
			paramNames = append(paramNames, paramName)
		}
		sort.Strings(paramNames)

		for _, paramName := range paramNames {
			paramValues := params[paramName]
			sort.Strings(paramValues)
			cr.WriteString("\n" + strings.ToLower(paramName) + ":" + strings.Join(paramValues, ","))
		}
	}
	return cr.String(), nil
}

func sendAzureRequest(req *http.Request, now time.Time, accountName, sharedKey string) (*http.Response, error) {
	cred, err := NewSharedKeyCredential(accountName, sharedKey)
	if err != nil {
		fmt.Println("Error creating credential:", err)
		return nil, err
	}

	// Setting universally required headers
	req.Header.Set("x-ms-date", now.Format(http.TimeFormat))
	req.Header.Set("x-ms-version", "2020-10-02")

	// Setting method-specific headers
	if req.Method == "PUT" || req.Method == "POST" {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", req.ContentLength))
		req.Header.Set("x-ms-blob-type", "BlockBlob")
	}

	stringToSign, err := cred.buildStringToSign(req)
	if err != nil {
		fmt.Println("Error building string to sign:", err)
		return nil, err
	}
	signature, err := cred.ComputeHMACSHA256(stringToSign)
	if err != nil {
		fmt.Println("Error computing signature:", err)
		return nil, err
	}
	authHeader := fmt.Sprintf("SharedKey %s:%s", accountName, signature)
	req.Header.Set("Authorization", authHeader)

	return spinhttp.Send(req)
}

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		// Retrieving Spin variables
		accountName, err := variables.Get("az_account_name")
		if err != nil {
			http.Error(w, "Error retrieving Azure account name", http.StatusInternalServerError)
		}

		sharedKey, err := variables.Get("az_shared_key")
		if err != nil {
			http.Error(w, "Error retrieving Azure shared_key", http.StatusInternalServerError)
		}

		host, err := variables.Get("az_host")
		if err != nil {
			http.Error(w, "Error retrieving Azure endpoint", http.StatusInternalServerError)
		}

		// Retrieving request headers
		uriPath := r.URL.Path
		endpoint := host + uriPath
		now := time.Now().UTC()

		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %s", err.Error()), http.StatusInternalServerError)
		}
		r.Body.Close()

		req, _ := http.NewRequest(r.Method, endpoint, bytes.NewReader(bodyData))

		resp, err := sendAzureRequest(req, now, accountName, sharedKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to execute outbound http request: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			http.Error(w, fmt.Sprintf("Response from outbound http request is not OK %v", resp.Status), http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read outbound http response: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		resp.Body.Close()

		w.WriteHeader(resp.StatusCode)

		if len(body) == 0 {
			w.Write([]byte("Response from Azure: " + resp.Status))
		} else {
			w.Write(body)
		}
	})
}

func main() {}

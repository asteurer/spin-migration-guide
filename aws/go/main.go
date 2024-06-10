package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	"github.com/fermyon/spin/sdk/go/v2/variables"
)

type AWSConfig struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	service         string
	host            string
}

type AWSFormattedDate struct {
	date     string // Formatted {YYYYMMDD}
	dateTime string // Formatted {YYYYMMDD}T{HHMMSS}Z
}

// Encodes a string to bytes using UTF-8 encoding
func encode(str string) []byte {
	return []byte(str)
}

// This creates a SHA256 hash of a byte array and returns a hex-encoded string
func getHash(payload []byte) string {
	hash := sha256.New()
	hash.Write(payload)

	return hex.EncodeToString(hash.Sum(nil))
}

func getRequestStrings(headers http.Header, queryParams map[string]string) (string, string, string) {
	// Formatted as header_key_1:header_value_1\nheader_key_2:header_value_2\n
	canonicalHeaders := ""
	// Formatted as header_key_1;header_key_2
	signedHeaders := ""
	headerKeys := make([]string, 0, len(headers))
	for key := range headers {
		headerKeys = append(headerKeys, key)
	}
	// Header names must appear in alphabetical order
	sort.Strings(headerKeys)

	for _, key := range headerKeys {
		// Each header name must use lowercase characters
		lowerCaseKey := strings.ToLower(key)
		canonicalHeaders += lowerCaseKey + ":" + headers.Get(key) + "\n"
		if signedHeaders == "" {
			signedHeaders += lowerCaseKey
		} else {
			signedHeaders += ";" + lowerCaseKey
		}
	}

	queryKeys := make([]string, 0, len(queryParams))
	for key := range queryParams {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	var canonicalQueryStringArray []string
	for _, key := range queryKeys {
		canonicalQueryStringArray = append(canonicalQueryStringArray, key+"="+queryParams[key])
	}
	canonicalQueryString := strings.Join(canonicalQueryStringArray, "&")

	return canonicalHeaders, signedHeaders, canonicalQueryString
}

// The numbered functions below correspond to the image in the article linked here: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
// 1. Canonical Request
func getCanonicalRequest(httpVerb, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload string) string {
	return strings.Join([]string{httpVerb, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload}, "\n")
}

// 2. StringToSign
func getStringToSign(config AWSConfig, formattedDate AWSFormattedDate, canonicalRequest string) string {
	scope := strings.Join([]string{formattedDate.date, config.region, config.service, "aws4_request"}, "/")

	return strings.Join([]string{"AWS4-HMAC-SHA256", formattedDate.dateTime, scope, getHash([]byte(canonicalRequest))}, "\n")
}

// 3. Signature
func getSignature(config AWSConfig, formattedDate AWSFormattedDate, stringToSign string) string {
	sign := func(key []byte, data []byte) []byte {
		hash := hmac.New(sha256.New, key)
		hash.Write(data)

		return hash.Sum(nil)
	}

	dateKey := sign(encode("AWS4"+config.secretAccessKey), encode(formattedDate.date))
	regionKey := sign(dateKey, encode(config.region))
	serviceKey := sign(regionKey, encode(config.service))
	signingKey := sign(serviceKey, encode("aws4_request"))

	return hex.EncodeToString(sign(signingKey, encode(stringToSign)))
}

func getAuthorizationHeader(config AWSConfig, formattedDate AWSFormattedDate, canonicalRequest, signedHeaders string) string {
	stringToSign := getStringToSign(config, formattedDate, canonicalRequest)
	signature := getSignature(config, formattedDate, stringToSign)
	credential := strings.Join([]string{config.accessKeyID, formattedDate.date, config.region, config.service, "aws4_request"}, "/")

	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s", credential, signedHeaders, signature)
}

func sendAwsHttpRequest(config AWSConfig, httpVerb, uriPath string, queryParams, headers map[string]string, payload []byte) (*http.Response, error) {
	// Getting the current time in UTC
	now := time.Now().UTC()
	formattedDate := AWSFormattedDate{
		date:     now.Format("20060102"),
		dateTime: now.Format("20060102T150405Z"),
	}

	if uriPath == "" || uriPath[0] != '/' {
		uriPath = "/" + uriPath
	}

	payloadHash := getHash(payload)
	if payloadHash == "" {
		return nil, fmt.Errorf("failed to generate hash for payload")
	}

	destinationUrl := "http://" + config.host + uriPath

	req, err := http.NewRequest(httpVerb, destinationUrl, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	// Adding extra headers
	for key, value := range headers {
		// Ensuring that the header keys are lowercase for proper signing.
		req.Header.Set(strings.ToLower(key), value)
	}

	// Keep in mind that these are the minimum headers required to interact with AWS. See the relevant service's API guide for any other required headers.
	req.Header.Set("host", config.host)
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("content-length", fmt.Sprintf("%d", len(payload)))
	// sessionToken is optional
	if config.sessionToken != "" {
		req.Header.Set("x-amz-security-token", config.sessionToken)
	}

	canonicalHeaders, signedHeaders, canonicalQueryString := getRequestStrings(req.Header, queryParams)
	canonicalRequest := getCanonicalRequest(httpVerb, uriPath, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash)

	req.Header.Set("authorization", getAuthorizationHeader(config, formattedDate, canonicalRequest, signedHeaders))

	// Spin adds the host header on it's own, so we need to delete it here to avoid a duplicate header error
	delete(headers, "host")

	return spinhttp.Send(req)
}

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		config, err := getConfig()
		if err != nil {
			fmt.Println("Failed to read configuration:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}

		// Read the request body
		payloadBytes, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println("Error reading request body:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		uriPath := r.Header.Get("x-uri-path")
		// If necessary, add query parameters: 'queryParams[key] = value'
		queryParams := make(map[string]string)
		// If necessary, add extra headers: 'headers[key] = value'
		headers := make(map[string]string)

		resp, err := sendAwsHttpRequest(config, r.Method, uriPath, queryParams, headers, payloadBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to execute outbound http request: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("response from outbound http request is not OK %v", resp.Status), http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read outbound http response: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		if len(body) == 0 {
			http.Error(w, fmt.Sprintf("outbound http response was empty\n"), http.StatusInternalServerError)
			return
		}

		// Set the status code from the response
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})
}

func main() {
	/*
	 *	In Spin environment, the handler function has to be wired up during the init function
	 *  because Spin will call into the wasi export named spin_http_handle_http_request
	 *  so we need to set the default handler during the init function which is called
	 *  before the exported spin_http_handle_http_request function in our SDK
	 *  spinhttp.Handle: https://github.com/fermyon/spin-go-sdk/blob/48ddef7a261725f771f987323b213b0696c655ef/http/http.go#L93
	 *  internals.go:    https://github.com/fermyon/spin-go-sdk/blob/48ddef7a261725f771f987323b213b0696c655ef/http/internals.go#L16
	 */
}

func getConfig() (AWSConfig, error) {
	accessKeyID, err := variables.Get("aws_access_key_id")
	if err != nil {
		return AWSConfig{}, err
	}
	secretAccessKey, err := variables.Get("aws_secret_access_key")
	if err != nil {
		return AWSConfig{}, err
	}
	sessionToken, err := variables.Get("aws_session_token")
	if err != nil {
		return AWSConfig{}, err
	}
	region, err := variables.Get("aws_default_region")
	if err != nil {
		return AWSConfig{}, err
	}
	service, err := variables.Get("aws_service")
	if err != nil {
		return AWSConfig{}, err
	}
	host, err := variables.Get("aws_host")
	if err != nil {
		return AWSConfig{}, err
	}

	config := AWSConfig{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		sessionToken:    sessionToken,
		region:          region,
		service:         service,
		host:            host,
	}

	return config, nil
}

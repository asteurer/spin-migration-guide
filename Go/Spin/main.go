package main

// TODO: Reject all requests that don't have content-type as a header.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		err := initConfig()
		if err != nil {
			fmt.Println("Failed to read configuration:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}
		router := spinhttp.NewRouter()
		router.GET("/*uriPath", routeRequest)
		router.PUT("/*uriPath", routeRequest)
		router.DELETE("/*uriPath", routeRequest)
		router.ServeHTTP(w, r)
	})
}

func routeRequest(w http.ResponseWriter, r *http.Request, p spinhttp.Params) {
	// uriPath := r.Header.Get("x-uri-path")
	uriPath := p.ByName("uriPath")
	fmt.Println(uriPath)
	payloadBytes, err := io.ReadAll(r.Body) // Read the request body
	if err != nil {
		fmt.Println("Error reading request body:", err)
		http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	request, err := buildAwsHttpRequest(r.Method, config.host, uriPath, make(map[string]string, 0), make(map[string]string, 0), bytes.NewReader(payloadBytes), 0)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create outbound http request: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	response, err := sendHttpRequest(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to send outgoing http get request: %v", err.Error()), http.StatusInternalServerError)
		return
	}

	if response.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("response from outbound http request is not OK:\n%v", response), http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read outbound http response: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if len(body) == 0 {
		http.Error(w, fmt.Sprintf("outbound http response was empty\n"), http.StatusInternalServerError)
		return
	}

	// Set the status code from the response
	w.WriteHeader(response.StatusCode)
	w.Write(body)
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

type AWSConfig struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	service         string
	host            string
}

var config AWSConfig

func initConfig() error {
	accessKeyID, err := variables.Get("aws_access_key_id")
	if err != nil {
		return err
	}
	secretAccessKey, err := variables.Get("aws_secret_access_key")
	if err != nil {
		return err
	}
	sessionToken, err := variables.Get("aws_session_token")
	if err != nil {
		return err
	}
	region, err := variables.Get("aws_default_region")
	if err != nil {
		return err
	}
	service, err := variables.Get("aws_service")
	if err != nil {
		return err
	}

	config = AWSConfig{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		sessionToken:    sessionToken,
		region:          region,
		service:         service,
		host:            service + "." + region + ".amazonaws.com",
	}

	return nil
}

func sendHttpRequest(req *http.Request) (*http.Response, error) {
	sender, _ := variables.Get("sender")
	switch sender {
	case "http.DefaultClient.Do":
		return http.DefaultClient.Do(req)
	case "":
		fallthrough
	case "spinhttp.Send":
		fallthrough
	default:
		return spinhttp.Send(req)
	}
}

func getStringToSign(canonicalRequest string, now time.Time) string {
	scope := now.Format("20060102") + "/" + config.region + "/" + config.service + "/aws4_request"

	return fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", now.Format("20060102T150405Z"), scope, hash([]byte(canonicalRequest)))
}

func getSignature(stringToSign string, now time.Time) string {
	sign := func(key []byte, data []byte) []byte {
		hash := hmac.New(sha256.New, key)
		hash.Write(data)
		return hash.Sum(nil)
	}

	// Create the signing key
	dateKey := sign([]byte("AWS4"+config.secretAccessKey), []byte(now.Format("20060102")))
	regionKey := sign(dateKey, []byte(config.region))
	serviceKey := sign(regionKey, []byte(config.service))
	signingKey := sign(serviceKey, []byte("aws4_request"))

	// Calculate the signature
	signature := sign(signingKey, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

func hash(payload []byte) string {
	hash := sha256.New()
	hash.Write(payload)
	return hex.EncodeToString(hash.Sum(nil))
}

func uriEncode(str string) string {
	return url.QueryEscape(str)
}

// buildCanonicalAndSignedHeaders formats the canonical and signed headers per AWS's requirements
// If a header is multi-value, the values must be a comma-separated string
func buildCanonicalAndSignedHeaders(queryParams map[string]string) (string, string) {
	paramKeys := make([]string, 0, len(queryParams))
	for key := range queryParams {
		// The headers list must include host and any that start with 'x-amz-'. The content-type header is optional, but must be included if present
		if key == "host" || key == "content-type" || strings.HasPrefix(strings.ToLower(key), "x-amz-") {
			paramKeys = append(paramKeys, key)
		}
	}
	// The header name must appear in alphabetical order
	sort.Strings(paramKeys)

	canonicalHeaders := ""
	// The signed headers are the same headers that are included in the canonical headers
	signedHeaders := ""
	for _, key := range paramKeys {
		lowerCaseKey := strings.ToLower(key) // The header name must be lowercase
		canonicalHeaders += lowerCaseKey + ":" + queryParams[key] + "\n"
		if signedHeaders == "" {
			signedHeaders += lowerCaseKey
		} else {
			signedHeaders += ";" + lowerCaseKey
		}
	}

	return canonicalHeaders, signedHeaders
}

func getCanonicalRequest(httpMethod, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload string) string {
	// TODO: Find ways to uriEncode the canonicalUri (not the slashes)
	return strings.Join([]string{httpMethod, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload}, "\n")
}

func getCanonicalQueryString(queryParams map[string]string) string {
	queryKeys := make([]string, 0, len(queryParams))
	for key := range queryParams {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)

	var queryStringArray []string
	for _, key := range queryKeys {
		param := uriEncode(key) + "=" + uriEncode(queryParams[key])
		queryStringArray = append(queryStringArray, param)
	}

	return strings.Join(queryStringArray, "&")
}

func buildAwsHttpRequest(httpMethod, host, canonicalUri string, queryParams map[string]string, payload io.Reader) (*http.Request, error) {
	canonicalQueryString := getCanonicalQueryString(queryParams)
	canonicalHeaders, signedHeaders = buildCanonicalAndSignedHeaders(queryParams)
	hashedPayload := nil
	canonicalRequest := getCanonicalRequest(httpMethod, canonicalUri, canonicalQueryString)

	queryParams["host"] = host
	// queryParams["content-type"] = http.DetectContentType(payload)
	// sessionToken may	not be required
	if config.sessionToken != "" {
		queryParams["x-amz-security-token"] = config.sessionToken
	}

	destinationUrl := "https://" + host + uriPath + "?" + queryString

	req, err := http.NewRequest(httpVerb, destinationUrl, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	return req, nil
}

// OLD BUILD AWS REQUEST

// now := time.Now().UTC()
// fmt.Printf("date: %s\n", now.Format("20060102"))
// fmt.Printf("dateTime: %s\n", now.Format("20060102T150405Z"))

// // Adding extra headers
// for key, value := range headers {
// 	// Ensuring that the header keys are lowercase for proper signing.
// 	req.Header.Set(strings.ToLower(key), value)
// }

// // Read payload to calculate hash and set it back to payload for request
// payloadBytes, err := io.ReadAll(payload)
// if err != nil {
// 	return nil, fmt.Errorf("failed to read payload: %w", err)
// }
// payloadReader := bytes.NewReader(payloadBytes)
// payloadHash := hash(payloadBytes)
// // TODO: Implement this:
// // contentType := http.DetectContentType(payloadBytes)
// req.Body = io.NopCloser(payloadReader)

// req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))
// req.Header.Set("x-amz-content-sha256", payloadHash)
// req.Header.Set("content-length", fmt.Sprintf("%d", contentLength))
// // sessionToken is optional
// if config.sessionToken != "" {
// 	req.Header.Set("x-amz-security-token", config.sessionToken)
// }

// canonicalHeaders, signedHeaders, canonicalQueryString := buildHeaderStrings(req.Header, queryParams)
// canonicalRequest := getCanonicalRequest(httpVerb, uriPath, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash)

// req.Header.Set("authorization", getAuthorizationHeader(now, canonicalRequest, signedHeaders))

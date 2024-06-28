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

type AZCredentials struct {
	accountName string
	accountKey  []byte
}

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		// Retrieving Spin variables
		accountName, err := variables.Get("az_account_name")
		if err != nil {
			http.Error(w, "Error retrieving Azure account name", http.StatusInternalServerError)
			return
		}

		sharedKey, err := variables.Get("az_shared_key")
		if err != nil {
			http.Error(w, "Error retrieving Azure shared_key", http.StatusInternalServerError)
			return
		}

		host, err := variables.Get("az_host")
		if err != nil {
			http.Error(w, "Error retrieving Azure endpoint", http.StatusInternalServerError)
			return
		}

		uriPath := r.URL.Path
		queryString := r.URL.RawQuery
		var endpoint string

		if len(queryString) == 0 {
			if uriPath == "/" {
				http.Error(w, fmt.Sprint("If you are not including a query string, you must have a more specific URI path (i.e. /containerName/path/to/object)"), http.StatusBadRequest)
				return
			} else {
				endpoint = host + uriPath
			}
		} else {
			endpoint = host + uriPath + "?" + queryString
		}

		// now := time.Now().UTC()
		now := time.Date(2024, 06, 01, 0, 0, 0, 0, time.UTC)

		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %s", err.Error()), http.StatusInternalServerError)
			return
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

func parseAZCredentials(accountName string, accountKey string) (*AZCredentials, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return nil, fmt.Errorf("Decode account key: %w", err)
	}
	return &AZCredentials{accountName: accountName, accountKey: decodedKey}, nil
}

func computeHMACSHA256(c *AZCredentials, message string) (string, error) {
	h := hmac.New(sha256.New, c.accountKey)
	_, err := h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), err
}

func buildStringToSign(c *AZCredentials, req *http.Request) (string, error) {
	getHeader := func(key string, headers http.Header) string {
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

	headers := req.Header
	contentLength := getHeader("Content-Length", headers)
	if contentLength == "0" {
		contentLength = ""
	}

	canonicalizedResource, err := buildCanonicalizedResource(c, req.URL)
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
		buildCanonicalizedHeader(headers),
		canonicalizedResource,
	}, "\n")

	fmt.Println("STRING TO SIGN:\n" + stringToSign)
	return stringToSign, nil
}

func buildCanonicalizedHeader(headers http.Header) string {
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
	sort.Strings(keys) // Canonicalized headers must be in lexicographical order

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

func buildCanonicalizedResource(c *AZCredentials, u *url.URL) (string, error) {
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
	cred, err := parseAZCredentials(accountName, sharedKey)
	if err != nil {
		fmt.Println("Error creating credential:", err)
		return nil, err
	}

	// Setting universally required headers
	req.Header.Set("x-ms-date", now.Format(http.TimeFormat))
	req.Header.Set("x-ms-version", "2020-10-02")

	// Setting method-specific headers
	if req.Method == "PUT" || req.Method == "POST" {
		req.Header.Set("content-length", fmt.Sprintf("%d", req.ContentLength))
		req.Header.Set("x-ms-blob-type", "BlockBlob")
	}

	stringToSign, err := buildStringToSign(cred, req)
	if err != nil {
		fmt.Println("Error building string to sign:", err)
		return nil, err
	}

	signature, err := computeHMACSHA256(cred, stringToSign)
	if err != nil {
		fmt.Println("Error computing signature:", err)
		return nil, err
	}
	authHeader := fmt.Sprintf("SharedKey %s:%s", accountName, signature)
	req.Header.Set("authorization", authHeader)

	return spinhttp.Send(req)
}

func main() {}

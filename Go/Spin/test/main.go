package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	"github.com/fermyon/spin/sdk/go/v2/variables"
)

type ApiObj struct {
	Id   string                 `json:"id,omitempty"`
	Name string                 `json:"name,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
}

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("1")
		apiReq, err := http.NewRequest("GET", "https://api.restful-api.dev/objects", bytes.NewReader(make([]byte, 0)))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create outbound http request: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		fmt.Println("2")
		apiRes, err := mySend(apiReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to execute outbound http request: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		if apiRes.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("response from outbound http request is not OK %v", apiRes.Status), http.StatusInternalServerError)
			return
		}

		fmt.Println("3")
		apiBody, err := io.ReadAll(apiRes.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read outbound http response: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		fmt.Println("4")
		if len(apiBody) == 0 {
			http.Error(w, fmt.Sprintf("outbound http response was empty\n"), http.StatusInternalServerError)
			return
		}

		fmt.Println("5")
		apiObjs := make([]ApiObj, 0)
		err = json.Unmarshal(apiBody, &apiObjs)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to decode outbound http response from json: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		fmt.Println("6")
		w.Header().Set("Content-Type", "application/json")
		we := json.NewEncoder(w)
		we.SetIndent("", "")
		we.Encode(apiObjs)
	})
}

func main() {}

func mySend(req *http.Request) (*http.Response, error) {
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

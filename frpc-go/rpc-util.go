package frpc

import (
	"fmt"
	"net/http"

	"bytes"
	"io/ioutil"

	"context"
)

func HttpGet(ctx context.Context, url string, reqBody string) (string, error) {
	return httpOperation(ctx, "GET", url, reqBody)
}

func HttpPost(ctx context.Context, url string, reqBody string) (string, error) {
	return httpOperation(ctx, "POST", url, reqBody)
}

func httpOperation(ctx context.Context, method string, url string, reqBody string) (string, error) {

	body := bytes.NewReader([]byte(reqBody))
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		fmt.Println("NewRequest error ", err.Error())
		return "", err
	}

	request.Header.Set("Content-Type", "application/json;charset=utf-8")
	request.Header.Set("Cache-Control", "no-cache")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return "", err
	}

	defer response.Body.Close()

	respBody, _ := ioutil.ReadAll(response.Body)

	return string(respBody), nil

}

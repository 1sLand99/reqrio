package reqrio

import (
	"encoding/hex"
	"encoding/json"
)

type Response struct {
	header Header
	body   []byte
}

func fromHexJson(hexStr string) (Response, error) {
	var resp Response
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return resp, err
	}
	var data map[string]interface{}
	err = json.Unmarshal(decoded, &data)
	if err != nil {
		return resp, err
	}
	header, err := parseHeaderJson(data["header"].(map[string]interface{}))
	if err != nil {
		return resp, err
	}
	resp.header = header
	body, err := hex.DecodeString(data["body"].(string))
	if err != nil {
		return resp, err
	}
	resp.body = body
	return resp, nil
}

func (resp *Response) Text() string {
	return string(resp.body)
}

func (resp *Response) StatusCode() int {
	return resp.header.status
}

func (resp *Response) Header() Header {
	return resp.header
}

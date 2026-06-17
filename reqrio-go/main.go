package main

import (
	"fmt"

	"github.com/xllgl2017/reqrio/reqrio-go/reqrio"
)

var headers = map[string]string{
	"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Accept":                    "*/*",
	"Sec-Fetch-Site":            "none",
	"Sec-Fetch-Mode":            "navigate",
	"Sec-Fetch-Dest":            "document",
	"sec-fetch-user":            "?1",
	"upgrade-insecure-requests": "1",
	"sec-ch-ua":                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
	"sec-ch-ua-mobile":          "?0",
	"sec-ch-ua-platform":        "\"Windows\"",
	"Accept-Language":           "zh-CN,zh;q=0.9",
	"Accept-Encoding":           "gzip,deflate,br,zstd",
	"Cache-Control":             "no-cache",
	"Connection":                "keep-alive",
}

func get() {
	session := reqrio.NewSession()
	err := session.SetHeaders(headers)
	if err != nil {
		panic(err)
	}
	resp, err := session.SendRequest(reqrio.ConnParam{
		Method: reqrio.GET,
		Url:    "https://www.baidu.com",
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())
	cookies, err := resp.Cookies()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", cookies[0])
	text, err := resp.Text()
	if err != nil {
		panic(err)
	}
	fmt.Println("body len: ", len(text))
	resp, err = session.SendRequest(reqrio.ConnParam{
		Method: reqrio.GET,
		Url:    "https://www.baidu.com",
		Params: map[string]string{
			"v": "1",
			"b": "{'ddfd':34}",
		},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())

}

func postForm() {
	session := reqrio.NewSession()
	resp, err := session.SendRequest(reqrio.ConnParam{
		Method: reqrio.POST,
		Url:    "https://www.baidu.com",
		Data: map[string]string{
			"v": "1",
			"b": "{'ddfd':34}",
		},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())
}

func postJson() {
	session := reqrio.NewSession()
	resp, err := session.SendRequest(reqrio.ConnParam{
		Method: reqrio.POST,
		Url:    "https://www.baidu.com",
		Json: map[string]any{
			"v": "1",
			"b": map[string]any{
				"ddfd": 34,
				"sdfg": false,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())
}

func postText() {
	session := reqrio.NewSession()
	resp, err := session.SendRequest(reqrio.ConnParam{
		Method:      reqrio.POST,
		Url:         "https://www.baidu.com",
		Bytes:       []byte("hello world, text"),
		ContentType: "text/plain",
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())
}

func postFiles() {
	session := reqrio.NewSession()
	err := session.SetKeyLog("../2.log")
	resp, err := session.SendRequest(reqrio.ConnParam{
		Method: reqrio.POST,
		Url:    "https://www.baidu.com",
		Data: map[string]string{
			"v": "1",
			"b": "{'ddfd':34}",
		},
		Files: []reqrio.HttpFile{
			reqrio.HttpFile{
				Path:      "2.log",
				FieldName: "file1",
			},
			reqrio.HttpFile{
				Path:      "2.log",
				FieldName: "file2",
			},
		},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Delete()
	fmt.Println(resp.StatusCode())
}

func main() {
	get()
	postForm()
	postJson()
	postText()
	postFiles()

}

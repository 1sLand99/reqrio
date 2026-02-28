package main
/*
git tag reqrio-go/v0.1.2
git push origin reqrio-go/v0.1.2
*/
import (
	"fmt"

	"github.com/xllgl2017/reqrio/reqrio-go/reqrio"
)

func main() {
	session := reqrio.NewSession()
	e1 := session.SetAlpn(reqrio.HTTP20)
	if e1 != nil {
		println(e1.Error())
	}
	headers := `{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Accept": "*/*",
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
		"sec-fetch-user": "?1",
		"upgrade-insecure-requests": "1",
		"sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
		"sec-ch-ua-mobile": "?0",
		"sec-ch-ua-platform": "\"Windows\"",
		"Accept-Language": "zh-CN,zh;q=0.9",
		"Accept-Encoding": "gzip,deflate,br,zstd",
		"Cache-Control": "no-cache",
		"Connection": "keep-alive"
	}`
	err1 := session.SetHeaderJson(headers)
	if err1 != nil {
		println(err1.Error())
	}
	session.SetRandomFingerprint("")
	err := session.SetUrl("https://m.so.com")
	if err != nil {
		println(err.Error())
		return
	}
	resp, err := session.Get()
	if err != nil {
		println(err.Error())
		return
	}
	println(resp.Text())
	fmt.Printf("%#v\n", resp.Header())
	session.Close()

	ws, err := reqrio.BuildWebSocket("wss://alive.github.com")
	if err != nil {
		return
	}
	err = ws.Open()
	if err != nil {
		return
	}
}

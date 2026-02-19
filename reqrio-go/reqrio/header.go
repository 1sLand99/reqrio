package reqrio

type Cookie struct {
	name     string
	value    string
	age      int
	domain   string
	path     string
	httpOnly bool
	secure   bool
	expires  string
	icpsp    bool
}

func parseJsonCookie(jc map[string]interface{}) Cookie {
	var cookie Cookie
	cookie.name = jc["name"].(string)
	cookie.value = jc["value"].(string)
	cookie.age = int(jc["age"].(float64))
	cookie.domain = jc["domain"].(string)
	cookie.path = jc["path"].(string)
	cookie.httpOnly = jc["http_only"].(bool)
	cookie.secure = jc["secure"].(bool)
	cookie.icpsp = jc["icpsp"].(bool)
	return cookie
}

type Header struct {
	uri       string
	method    Method
	status    int
	agreement string
	keys      map[string]interface{}
	cookies   []Cookie
}

func parseHeaderJson(headers map[string]interface{}) (Header, error) {
	var header Header
	header.uri = headers["uri"].(string)
	method, err := ParseStringMethod(headers["method"].(string))
	if err != nil {
		return header, err
	}
	header.method = method
	header.status = int(headers["status"].(float64))
	header.agreement = headers["agreement"].(string)
	keys := headers["keys"].(map[string]interface{})
	setCookies := keys["Set-Cookie"]
	if setCookies != nil {
		for _, cookie := range setCookies.([]interface{}) {
			header.cookies = append(header.cookies, parseJsonCookie(cookie.(map[string]interface{})))
		}
	}

	setCookies2 := keys["set-cookie"]
	if setCookies2 != nil {
		for _, cookie := range setCookies2.([]interface{}) {
			header.cookies = append(header.cookies, parseJsonCookie(cookie.(map[string]interface{})))
		}
	}

	delete(keys, "Set-Cookie")
	delete(keys, "set-cookie")
	header.keys = make(map[string]interface{})
	for key, value := range headers["keys"].(map[string]interface{}) {
		header.keys[key] = value.(string)
	}
	return header, nil
}

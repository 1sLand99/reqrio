package reqrio

/*
#include <stdint.h>
#include <stdbool.h>

#cgo LDFLAGS: -LD:/projects/rust/reqrio/target/x86_64-pc-windows-gnu/release -lreqrio
extern void * ScReq_new();
extern int ScReq_set_header_json(void *req, const char *headers);
extern int ScReq_add_header(void *req, const char *name, char *value);

extern int ScReq_set_alpn(void *req, const char *alpn);
extern int ScReq_set_random_fingerprint(void *req, const char *token);
extern int ScReq_set_fingerprint(void *req, const char *fingerprint, const char *token);
extern int ScReq_set_ja3(void *req, const char *ja3, const char *token);
extern int ScReq_set_ja4(void *req, const char *ja4, const char *token);

extern int ScReq_set_proxy(void *req, const char *alpn);
extern int ScReq_set_url(void *req, const char *alpn);
extern int ScReq_add_param(void *req, const char *name, const char *value);
extern int ScReq_set_data(void *req, const char *data);
extern int ScReq_set_json(void *req, const char *json);
extern int ScReq_set_bytes(void *req, const char *bytes, uint32_t len);
extern int ScReq_set_text(void *req, const char *text);
extern int ScReq_set_timeout(void *req, const char *timeout);
extern int ScReq_set_cookie(void *req, const char *cookie);
extern int ScReq_add_cookie(void *req, const char *name,const char *value);
//callback
extern char * ScReq_stream_io(void *req, int method);
extern int ScReq_reconnect(void *req);
extern void ScReq_drop(void *req);
extern int char_free(char *);
*/
import "C"
import (
	"errors"
	"unsafe"
)

type ALPN string

const (
	HTTP20 ALPN = "h2"
	HTTP11 ALPN = "http/1.1"
)

type Session struct {
	req unsafe.Pointer
}

func NewSession() Session {
	p := C.ScReq_new()
	return Session{req: p}
}

func (session *Session) SetHeaderJson(header string) error {
	ret := C.ScReq_set_header_json(session.req, C.CString(header))
	if ret == -1 {
		return errors.New("set header error")
	}
	return nil
}

func (session *Session) AddHeader(name string, value string) error {
	ret := C.ScReq_add_header(session.req, C.CString(name), C.CString(value))
	if ret == -1 {
		return errors.New("add header error")
	}
	return nil
}

func (session *Session) SetAlpn(alpn ALPN) error {
	ret := C.ScReq_set_alpn(session.req, C.CString(string(alpn)))
	if ret == -1 {
		return errors.New("set alpn error")
	}
	return nil
}

func (session *Session) SetRandomFingerprint(token string) error {
	ret := C.ScReq_set_random_fingerprint(session.req, C.CString(token))
	if ret == -1 {
		return errors.New("set random fingerprint error")
	}
	return nil
}

func (session *Session) SetFingerprint(fingerprint string, token string) error {
	ret := C.ScReq_set_fingerprint(session.req, C.CString(fingerprint), C.CString(token))
	if ret == -1 {
		return errors.New("set fingerprint error")
	}
	return nil
}

func (session *Session) SetJa3(ja3 string, token string) error {
	ret := C.ScReq_set_ja3(session.req, C.CString(ja3), C.CString(token))
	if ret == -1 {
		return errors.New("set ja3 error")
	}
	return nil
}

func (session *Session) SetJa4(ja4 string, token string) error {
	ret := C.ScReq_set_ja4(session.req, C.CString(ja4), C.CString(token))
	if ret == -1 {
		return errors.New("set ja4 error")
	}
	return nil
}

func (session *Session) SetProxy(proxy string) error {
	ret := C.ScReq_set_proxy(session.req, C.CString(proxy))
	if ret == -1 {
		return errors.New("set proxy error")
	}
	return nil
}

func (session *Session) SetUrl(url string) error {
	ret := C.ScReq_set_url(session.req, C.CString(url))
	if ret == -1 {
		return errors.New("session url set error")
	}
	return nil
}

func (session *Session) AddParam(name string, value string) error {
	ret := C.ScReq_add_param(session.req, C.CString(name), C.CString(value))
	if ret == -1 {
		return errors.New("sc add param error")
	}
	return nil
}

func (session *Session) SetData(name string) error {
	ret := C.ScReq_set_data(session.req, C.CString(name))
	if ret == -1 {
		return errors.New("sc set data error")
	}
	return nil

}

func (session *Session) SetJson(json string) error {
	ret := C.ScReq_set_json(session.req, C.CString(json))
	if ret == -1 {
		return errors.New("sc set json error")
	}
	return nil
}

func (session *Session) SetBytes(bytes []byte) error {
	ret := C.ScReq_set_bytes(session.req, (*C.char)(unsafe.Pointer(&bytes[0])), C.uint32_t(len(bytes)))
	if ret == -1 {
		return errors.New("sc set bytes error")
	}
	return nil
}

func (session *Session) SetText(text string) error {
	ret := C.ScReq_set_text(session.req, C.CString(text))
	if ret == -1 {
		return errors.New("sc set text error")
	}
	return nil
}

func (session *Session) SetTimeout(timeout string) error {
	ret := C.ScReq_set_timeout(session.req, C.CString(timeout))
	if ret == -1 {
		return errors.New("sc set timeout error")
	}
	return nil
}

func (session *Session) SetCookie(cookie string) error {
	ret := C.ScReq_set_cookie(session.req, C.CString(cookie))
	if ret == -1 {
		return errors.New("sc set cookie error")
	}
	return nil
}

func (session *Session) AddCookie(name string, value string) error {
	ret := C.ScReq_add_cookie(session.req, C.CString(name), C.CString(value))
	if ret == -1 {
		return errors.New("add cookie error")
	}
	return nil
}

func (session *Session) sendRequest(method Method) (Response, error) {
	ptr := C.ScReq_stream_io(session.req, C.int(method))
	defer C.char_free(ptr)
	resp, err := fromHexJson(C.GoString(ptr))
	if err != nil {
		return resp, err
	}
	resp.header.method = method
	return resp, nil
}

func (session *Session) reconnect() error {
	ret := C.ScReq_reconnect(session.req)
	if ret == -1 {
		return errors.New("reconnect error")
	}
	return nil
}

func (session *Session) Get() (Response, error) {
	return session.sendRequest(GET)
}

func (session *Session) Post() (Response, error) {
	return session.sendRequest(POST)
}

func (session *Session) Put() (Response, error) {
	return session.sendRequest(PUT)
}

func (session *Session) Delete() (Response, error) {
	return session.sendRequest(DELETE)
}

func (session *Session) Head() (Response, error) {
	return session.sendRequest(HEAD)
}

func (session *Session) Options() (Response, error) {
	return session.sendRequest(OPTIONS)
}

func (session *Session) Trace() (Response, error) {
	return session.sendRequest(TRACE)
}

func (session *Session) Patch() (Response, error) {
	return session.sendRequest(PATCH)
}

func (session *Session) Close() {
	C.ScReq_drop(session.req)
}

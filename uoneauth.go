package uoneauth

// #cgo CXXFLAGS: -std=c++0x -Wall -fno-strict-aliasing
// #cgo LDFLAGS: -lstdc++
// #cgo pkg-config: ubuntuoneauth-2.0
//
// #include "uoneauth.h"
//
import "C"

import (
	"errors"
	"unsafe"

	"gopkg.in/v0/qml"
	"runtime"
	"strings"
	"sync"
	"unicode"
)

// Service communicates with the system and with Ubuntu One to obtain
// credentials for creating authentication tokens.
type Service struct {
	mu    sync.Mutex
	reply chan reply
	obj   qml.Common
}

// NewService returns a new Service.
func NewService(engine *qml.Engine) *Service {
	s := &Service{}
	s.reply = make(chan reply, 5)

	qml.RunMain(func() {
		s.obj = *qml.CommonOf(C.newSSOService(), engine)
		runtime.SetFinalizer(s, (*Service).finalize)
	})

	s.obj.On("credentialsFound", s.credentialsFound)
	s.obj.On("credentialsNotFound", s.credentialsNotFound)
	s.obj.On("twoFactorAuthRequired", s.twoFactorAuthRequired)
	s.obj.On("requestFailed", s.requestFailed)
	return s
}

// Close destroys the service and releases any used resources.
func (s *Service) Close() {
	s.finalize()
	runtime.SetFinalizer(s, nil)
}

func (s *Service) finalize() {
	qml.RunMain(func() {
		C.ssoServiceDelete(unsafe.Pointer(s.obj.Addr()))
	})
}

// Token returns a token that can authenticate access to specified URLs
// via HTTP header or URL query signatures, on behalf of the user with
// Ubuntu One credentials registered on the system.
func (s *Service) Token() (*Token, error) {
	s.mu.Lock()
	qml.RunMain(func() {
		C.ssoServiceGetCredentials(unsafe.Pointer(s.obj.Addr()))
	})
	reply := <-s.reply
	s.mu.Unlock()
	return reply.token, reply.err
}

// Token represents an authentication token associated with the
// credentials in use by a Service.
type Token struct {
	addr unsafe.Pointer
}

// HeaderSignature returns the HTTP header value that authenticates access
// via the provided HTTP method to the specified URL.
func (t *Token) HeaderSignature(method, url string) string {
	cmethod := C.CString(method)
	curl := C.CString(url)
	cheader := C.tokenSignURL(t.addr, cmethod, curl, 0)
	header := C.GoString(cheader)
	C.free(unsafe.Pointer(cmethod))
	C.free(unsafe.Pointer(curl))
	C.free(unsafe.Pointer(cheader))
	return header
}

// QuerySignature returns the URL query value that authenticates access
// via the provided HTTP method to the specified URL.
func (t *Token) QuerySignature(method, url string) string {
	cmethod := C.CString(method)
	curl := C.CString(url)
	cquery := C.tokenSignURL(t.addr, cmethod, curl, 1)
	query := C.GoString(cquery)
	C.free(unsafe.Pointer(cmethod))
	C.free(unsafe.Pointer(curl))
	C.free(unsafe.Pointer(cquery))
	return query
}

// Close destroys the token and releases any used resources.
func (t *Token) Close() {
	t.finalize()
	runtime.SetFinalizer(t, nil)
}

func (t *Token) finalize() {
	qml.RunMain(func() {
		C.tokenDelete(unsafe.Pointer(t.addr))
	})
}

var (
	ErrNoCreds   = errors.New("credentials not found")
	ErrTwoFactor = errors.New("two-factor authentication required")
)

type RequestError struct {
	msg string
}

func (e *RequestError) Error() string {
	return e.msg
}

type reply struct {
	token *Token
	err   error
}

func (s *Service) credentialsFound(token *Token) {
	s.reply <- reply{token: token}
}

func (s *Service) credentialsNotFound() {
	s.reply <- reply{err: ErrNoCreds}
}

func (s *Service) twoFactorAuthRequired() {
	s.reply <- reply{err: ErrTwoFactor}
}

func (s *Service) requestFailed(err *RequestError) {
	s.reply <- reply{err: err}
}

func convertToken(engine *qml.Engine, obj qml.Object) interface{} {
	// Must copy as the one held by obj may be deallocated once the signal is done.
	token := &Token{C.tokenCopy(unsafe.Pointer(obj.Property("valueAddr").(uintptr)))}
	runtime.SetFinalizer(token, (*Token).finalize)
	return token
}

func convertErrorResponse(engine *qml.Engine, obj qml.Object) interface{} {
	cmsg := C.errorResponseString(unsafe.Pointer(obj.Property("valueAddr").(uintptr)))
	msg := C.GoString(cmsg)
	C.free(unsafe.Pointer(cmsg))

	// Drop C++ code reference.
	const onReplyPrefix = "Network::OnReply:"
	if strings.HasPrefix(msg, onReplyPrefix) {
		msg = strings.TrimLeft(msg[len(onReplyPrefix):], " ")
	}

	// Lowercase error messages, per Go conventions.
	var r0 rune
	for i, r := range msg {
		if i == 0 {
			if unicode.IsUpper(r) {
				r0 = r
				continue
			}
		} else if unicode.IsLower(r) || unicode.IsSpace(r) {
			msg = string(unicode.ToLower(r0)) + msg[i:]
		}
		break
	}

	return &RequestError{msg: msg}
}

func init() {
	qml.RegisterConverter("Token", convertToken)
	qml.RegisterConverter("ErrorResponse", convertErrorResponse)
}

package gomail

import (
	"errors"
	"fmt"
	"net/smtp"

	"github.com/Azure/go-ntlmssp"
)

// 出于业务需要我们对如下鉴权机制进行了支持 LOGIN PLAIN NTLM CRAM-MD5
// 重点支持了 LOGIN PLAIN（适用最广泛）

const (
	loginMechanism = "LOGIN"
	plainMechanism = "PLAIN"
	ntlmMechanism  = "NTLM"
)

// loginAuth is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginAuth struct {
	username string
	password string
	// host     string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// if !server.TLS {
	// advertised := false
	// for _, mechanism := range server.Auth {
	// 	if mechanism == loginMechanism {
	// 		advertised = true
	// 		break
	// 	}
	// }
	// if !advertised {
	// 	return "", nil, errors.New("gomail: unencrypted connection")
	// }
	// }
	// if server.Name != a.host {
	// 	return "", nil, errors.New("gomail: wrong host name")
	// }
	return loginMechanism, []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}

	// switch {
	// case bytes.Equal(fromServer, []byte("Username:")):
	// 	return []byte(a.username), nil
	// case bytes.Equal(fromServer, []byte("Password:")):
	// 	return []byte(a.password), nil
	// default:
	// 	return nil, fmt.Errorf("gomail: unexpected server challenge: %s", fromServer)
	// }
	switch string(fromServer) {
	case "Username:":
		return []byte(a.username), nil
	case "Password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unknown fromServer: %s", string(fromServer))
	}
}

type plainAuth struct {
	username, password string
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Must have TLS, or else localhost server.
	// Note: If TLS is not true, then we can't trust ANYTHING in ServerInfo.
	// In particular, it doesn't matter if the server advertises PLAIN auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your password."
	//if !server.TLS && !isLocalhost(server.Name) {
	//	return "", nil, errors.New("unencrypted connection")
	//}
	//if server.Name != a.host {
	//	return "", nil, errors.New("wrong host name")
	//}
	resp := []byte("" + "\x00" + a.username + "\x00" + a.password)
	return plainMechanism, resp, nil
}

func (a *plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type ntlmAuth struct {
	username, password, domain string
	domainNeeded               bool
}

// NtlmAuth SMTP AUTH NTLM Auth Handler
func NtlmAuth(username, password string) smtp.Auth {
	user, domain, domainNeeded := ntlmssp.GetDomain(username)
	return &ntlmAuth{user, password, domain, domainNeeded}
}

// Start starts SMTP NTLM Auth
func (a *ntlmAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	negotiateMessage, err := ntlmssp.NewNegotiateMessage(a.domain, "")
	return "NTLM", negotiateMessage, err
}

// Next next step of SMTP ntlm auth
func (a *ntlmAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		if len(fromServer) == 0 {
			return nil, fmt.Errorf("ntlm ChallengeMessage is empty")
		}
		authenticateMessage, err := ntlmssp.ProcessChallenge(fromServer, a.username, a.password, a.domainNeeded)
		return authenticateMessage, err
	}
	return nil, nil
}

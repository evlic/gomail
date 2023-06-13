package gomail

import (
	"fmt"
	"net/smtp"

	"github.com/Azure/go-ntlmssp"
)

const loginMechanism = "LOGIN"

// LoginAuth is an smtp.Auth that implements the LOGIN authentication mechanism.
type LoginAuth struct {
	username string
	password string
	// host     string
}

func (a *LoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
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

func (a *LoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
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
package caddy_fail2ban

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Fail2Ban{})
}

// Fail2Ban implements an HTTP handler that checks a specified file for banned
// IPs and matches if they are found
type Fail2Ban struct {
	Banfile string `json:"banfile"`

	logger  *zap.Logger
	banlist Banlist
}

// CaddyModule returns the Caddy module information.
func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Fail2Ban) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.banlist = NewBanlist(ctx, m.logger, &m.Banfile)
	m.banlist.Start()
	return nil
}

func (m *Fail2Ban) Match(req *http.Request) bool {
        remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
        if err != nil {
                m.logger.Error("Error parsing remote addr into IP & port", zap.String("remote_addr", req.RemoteAddr), zap.Error(err))
                // Deny by default
                return true
        }

        const trustedProxy = "10.10.4.99" // the known proxy address

        // will try to extract the client ip from the headers only if we are coming from the trusted proxy
        var clientIP string
        if remoteIP == trustedProxy {
                if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
                        clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
                	m.logger.Info("Using X-Forwareded-For")
                } else if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
                        clientIP = strings.TrimSpace(xrip)
                	m.logger.Info("Using X-Real-IP")
                } else {
                        clientIP = remoteIP
                	m.logger.Info("No X-Forwareded-For or X-Real-IP headers, using remote_ip")
                }
        } else {
                clientIP = remoteIP
                m.logger.Debug("Not Trusted Proxy using remote_ip")
        }


        // Only ban if header X-Caddy-Ban is sent
        _, ok := req.Header["X-Caddy-Ban"]
        if ok {
                m.logger.Info("banned IP", zap.String("remote_ip", remoteIP), zap.String("clientIP", clientIP))
                return true
        }

        if m.banlist.IsBanned(clientIP) == true {
                m.logger.Info("banned IP", zap.String("client_ip", clientIP))
                return true
        }

	m.logger.Debug("received request", zap.String("remote_ip", remoteIP))
        return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Fail2Ban) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		switch v := d.Val(); v {
		case "fail2ban":
			if !d.Next() {
				return fmt.Errorf("fail2ban expects file path, value is missing")
			}
			m.Banfile = d.Val()
		default:
			return fmt.Errorf("unknown config value: %s", v)

		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner        = (*Fail2Ban)(nil)
	_ caddyhttp.RequestMatcher = (*Fail2Ban)(nil)
	_ caddyfile.Unmarshaler    = (*Fail2Ban)(nil)
)

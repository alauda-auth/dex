package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dexidp/dex/storage"
)

// types
type AuthErr struct {
	*authErr
}

func NewSever(c Config) (*Server, error) {
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	supported := make(map[string]bool)
	for _, respType := range c.SupportedResponseTypes {
		switch respType {
		case responseTypeCode, responseTypeIDToken, responseTypeToken:
		default:
			return nil, fmt.Errorf("unsupported response_type %q", respType)
		}
		supported[respType] = true
	}

	now := c.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		issuerURL:              *issuerURL,
		connectors:             make(map[string]Connector),
		storage:                newKeyCacher(c.Storage, now),
		supportedResponseTypes: supported,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		authRequestsValidFor:   value(c.AuthRequestsValidFor, 24*time.Hour),
		deviceRequestsValidFor: value(c.DeviceRequestsValidFor, 5*time.Minute),
		skipApproval:           c.SkipApprovalScreen,
		alwaysShowLogin:        c.AlwaysShowLoginScreen,
		now:                    now,
		templates:              nil,
		passwordConnector:      c.PasswordConnector,
		logger:                 c.Logger,
	}
	return s, nil
}

// method
func (s *Server) IsAlwaysShowLogin() bool {
	return s.alwaysShowLogin
}

func (s *Server) ParseAuthorizationRequest(r *http.Request) (*storage.AuthRequest, error) {
	return s.parseAuthorizationRequest(r)
}

func (s *Server) Connectors() map[string]Connector {
	return s.connectors
}

// handler
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	s.handleToken(w, r)
}

func (s *Server) HandlePublicKeys(w http.ResponseWriter, r *http.Request) {
	s.handlePublicKeys(w, r)
}

func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	s.handleUserInfo(w, r)
}

func (s *Server) HandleAuthorization(w http.ResponseWriter, r *http.Request) {
	s.handleAuthorization(w, r)
}

func (s *Server) HandleConnectorLogin(w http.ResponseWriter, r *http.Request) {
	s.handleConnectorLogin(w, r)
}

func (s *Server) HandleDeviceExchange(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceExchange(w, r)
}

func (s *Server) VerifyUserCode(w http.ResponseWriter, r *http.Request) {
	s.verifyUserCode(w, r)
}

func (s *Server) HandleDeviceCode(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceCode(w, r)
}

func (s *Server) HandleDeviceToken(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceToken(w, r)
}

func (s *Server) HandleDeviceCallback(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceCallback(w, r)
}

// worker
func (s *Server) StartKeyRotation(ctx context.Context, c Config, now func() time.Time) {
	strategy := defaultRotationStrategy(
		value(c.RotateKeysAfter, 6*time.Hour),
		value(c.IDTokensValidFor, 24*time.Hour),
	)
	s.startKeyRotation(ctx, strategy, now)
}

func (s *Server) StartGarbageCollection(ctx context.Context, frequency time.Duration, now func() time.Time) {
	s.startGarbageCollection(ctx, frequency, now)
}

func Value(val, defaultValue time.Duration) time.Duration {
	return value(val, defaultValue)
}

package server

import (
	"context"
	"fmt"
	"github.com/dexidp/dex/connector"
	"net/http"
	"net/url"
	"time"

	"github.com/dexidp/dex/storage"
)

// types
type AuthErr struct {
	*authErr
}

func New(c Config) (*Server, error) {
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}
	if c.Storage == nil {
		return nil, fmt.Errorf("server: storage cannot be nil")
	}
	if len(c.SupportedResponseTypes) == 0 {
		c.SupportedResponseTypes = []string{responseTypeCode}
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

	// Retrieves connector objects in backend storage. This list includes the static connectors
	// defined in the ConfigMap and dynamic connectors retrieved from the storage.
	storageConnectors, err := c.Storage.ListConnectors()
	if err != nil {
		return nil, fmt.Errorf("server: failed to list connector objects from storage: %v", err)
	}

	if len(storageConnectors) == 0 && len(s.connectors) == 0 {
		return nil, fmt.Errorf("server: no connectors specified")
	}

	for _, conn := range storageConnectors {
		if _, err := s.OpenConnector(conn); err != nil {
			return nil, fmt.Errorf("server: Failed to open connector %s: %v", conn.ID, err)
		}
	}

	return s, nil
}

// method
func (s *Server) IssuerURL() url.URL {
	return s.issuerURL
}

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

func (s *Server) HandleConnectorCallback(w http.ResponseWriter, r *http.Request) {
	s.handleConnectorCallback(w, r)
}

func (s *Server) HandleApproval(w http.ResponseWriter, r *http.Request) {
	s.handleApproval(w, r)
}
func (s *Server) DiscoveryHandler() (http.HandlerFunc, error) {
	return s.discoveryHandler()
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

func (s *Server) AuthRequestsValidFor() time.Duration {
	return s.authRequestsValidFor
}

func (s *Server) Now() func() time.Time {
	return s.now
}
func (s *Server) AbsPath(pathItems ...string) string {
	return s.absPath(pathItems...)
}

func (s *Server) AbsURL(pathItems ...string) string {
	return s.absURL(pathItems...)
}

func (s *Server) TokenErrHelper(w http.ResponseWriter, typ string, description string, statusCode int) {
	s.tokenErrHelper(w, typ, description, statusCode)
}

func (s *Server) GetConnector(id string) (Connector, error) {
	return s.getConnector(id)
}

func (s *Server) FinalizeLogin(identity connector.Identity, authReq storage.AuthRequest, conn connector.Connector) (string, error) {
	return s.finalizeLogin(identity, authReq, conn)
}

// function
func ParseScopes(scopes []string) connector.Scopes {
	return parseScopes(scopes)
}

package safeweb

import (
	crand "crypto/rand"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
)

type Options struct {
	Hostname                    string
	ApplicationHandler          http.Handler
	PermittedCrossOriginHosts   []string
	PermittedCrossOriginMethods []string

	ServeHTTPS bool
	// ServeHTTP                   bool
	// RedirectHTTPS               bool

	csrfProtect func(http.Handler) http.Handler
}

func (o *Options) setDefaults() {
	if o.ApplicationHandler == nil {
		o.ApplicationHandler = &http.ServeMux{}
	}

	if len(o.PermittedCrossOriginMethods) == 0 {
		o.PermittedCrossOriginMethods = []string{"GET", "POST", "OPTIONS"}
	}
}

type Server struct {
	Options
	h *http.Server
}

func wrapHandler(opts Options) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			// disallow `application/x-www-form-urlencoded` content-type for POST requests to /api/*
			case "POST", "PUT", "PATCH":
				if strings.HasPrefix(r.URL.Path, "/api/") {
					if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
						http.Error(w, "invalid content type", http.StatusBadRequest)
						return
					}
				}

			// set CORS headers for pre-flight OPTIONS requests if any were configured
			case "OPTIONS":
				if len(opts.PermittedCrossOriginHosts) > 0 {
					w.Header().Set("Access-Control-Allow-Origin", strings.Join(opts.PermittedCrossOriginHosts, ", "))
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(opts.PermittedCrossOriginMethods, ", "))
				}
			}

			// apply CSRF protection to non-API routes
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				opts.csrfProtect(h).ServeHTTP(w, r)
			} else {
				h.ServeHTTP(w, r)
			}
		})
	}
}

func NewServer(opts Options) (*Server, error) {
	opts.setDefaults()

	k := make([]byte, 32)
	if _, err := crand.Read(k); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}
	opts.csrfProtect = csrf.Protect(k, csrf.Secure(opts.ServeHTTPS))

	return &Server{
		opts,
		&http.Server{Handler: wrapHandler(opts)(opts.ApplicationHandler)},
	}, nil
}

func (s *Server) Serve(ln net.Listener) error {
	return s.h.Serve(ln)
}

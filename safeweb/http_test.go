package safeweb

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
	"golang.org/x/net/nettest"
)

func TestPostRequestContentTypeValidation(t *testing.T) {
	tests := []struct {
		name        string
		route       string
		contentType string
		wantErr     bool
	}{
		{
			name:        "`/api/*` routes should accept `application/json` content-type",
			route:       "/api/foo",
			contentType: "application/json",
			wantErr:     false,
		},
		{
			name:        "`/api/*` routes should reject `application/x-www-form-urlencoded` content-type",
			route:       "/api/foo",
			contentType: "application/x-www-form-urlencoded",
			wantErr:     true,
		},
		{
			name:        "non `/api/*` routes should accept `application/x-www-form-urlencoded` content-type",
			route:       "/foo",
			contentType: "application/x-www-form-urlencoded",
			wantErr:     false,
		},
		{
			name:        "non `/api/*` routes should accept `application/json` content-type",
			route:       "/foo",
			contentType: "application/json",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle(tt.route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Options{ApplicationHandler: h})
			if err != nil {
				t.Fatal(err)
			}

			l, err := nettest.NewLocalListener("tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go s.Serve(l)

			client := &http.Client{}
			req, err := http.NewRequest("POST", "http://"+l.Addr().String()+tt.route, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", tt.contentType)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantErr && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("content type validation failed: got %v; want %v", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestCrossOriginResourceSharingHeaders(t *testing.T) {
	tests := []struct {
		name            string
		httpMethod      string
		wantCORSHeaders bool
		corsOrigins     []string
		corsMethods     []string
	}{
		{
			name:            "do not set CORS headers for non-OPTIONS requests",
			corsOrigins:     []string{"https://foobar.com"},
			httpMethod:      "GET",
			wantCORSHeaders: false,
		},
		{
			name:            "set CORS headers for non-OPTIONS requests",
			corsOrigins:     []string{"https://foobar.com"},
			httpMethod:      "OPTIONS",
			wantCORSHeaders: true,
			corsMethods:     []string{"GET", "POST", "HEAD"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Options{
				ApplicationHandler:        h,
				PermittedCrossOriginHosts: tt.corsOrigins,
			})
			if err != nil {
				t.Fatal(err)
			}
			l, err := nettest.NewLocalListener("tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go s.Serve(l)

			client := &http.Client{}
			req, err := http.NewRequest(tt.httpMethod, "http://"+l.Addr().String()+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if (resp.Header.Get("Access-Control-Allow-Origin") == "") == tt.wantCORSHeaders {
				t.Fatalf("access-control-allow-origin want: %v; got: %v", tt.wantCORSHeaders, resp.Header.Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestBrowserCrossOriginRequestForgeryProtection(t *testing.T) {
	tests := []struct {
		name          string
		route         string
		passCSRFToken bool
		wantStatus    int
	}{
		{
			name:          "POST requests to non-API routes require CSRF token and fail if not provided",
			route:         "/foo",
			passCSRFToken: false,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "POST requests to non-API routes require CSRF token and pass if provided",
			route:         "/foo",
			passCSRFToken: true,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "POST requests to /api/ routes do not require CSRF token",
			route:         "/api/foo",
			passCSRFToken: false,
			wantStatus:    http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle(tt.route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Options{ApplicationHandler: h})
			if err != nil {
				t.Fatal(err)
			}
			l, err := nettest.NewLocalListener("tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go s.Serve(l)

			client := &http.Client{Jar: http.CookieJar(nil)}
			target := "http://" + l.Addr().String()

			// construct the test request
			req, err := http.NewRequest("POST", target+tt.route, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Referer", target)

			if strings.HasPrefix(tt.route, "/api/") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			// retrieve CSRF cookie & pass it in the test request
			// ref: https://github.com/gorilla/csrf/blob/main/csrf_test.go#L344-L347
			var token string
			if tt.passCSRFToken {
				h.Handle("/csrf", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					token = csrf.Token(r)
				}))
				get, err := http.NewRequest("GET", target+"/csrf", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(get)
				if err != nil {
					t.Fatal(err)
				}

				// pass the token & cookie in our subsequent test request
				req.Header.Set("X-CSRF-Token", token)
				for _, c := range resp.Cookies() {
					req.AddCookie(c)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("csrf protection check failed: got %v; want %v", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

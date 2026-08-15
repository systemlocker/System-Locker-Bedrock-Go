package bedrock

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPResponse is the transport-neutral result of one HTTP exchange.
// Transport-level failures set Err; HTTP status is always captured.
// Header keys are lowercase.
type HTTPResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
	Err        error
}

// OK reports a transport-level success with a 2xx status.
func (r HTTPResponse) OK() bool {
	return r.Err == nil && r.StatusCode >= 200 && r.StatusCode < 300
}

// Header returns a header value case-insensitively, or "" when absent.
func (r HTTPResponse) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// HTTPClient abstracts the two operations the library performs. Inject a
// fake in tests; DefaultHTTPClient is used otherwise.
type HTTPClient interface {
	PostForm(ctx context.Context, rawURL string, fields url.Values, headers map[string]string) HTTPResponse
	Get(ctx context.Context, rawURL string, headers map[string]string) HTTPResponse
}

// DefaultHTTPClient performs real requests with net/http.
type DefaultHTTPClient struct {
	HTTP  *http.Client
	Agent string
}

// NewDefaultHTTPClient builds a DefaultHTTPClient with the given timeout and
// user agent.
func NewDefaultHTTPClient(timeout time.Duration, userAgent string) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		HTTP: &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		Agent: userAgent,
	}
}

func (d *DefaultHTTPClient) do(ctx context.Context, req *http.Request) HTTPResponse {
	if d.Agent != "" {
		req.Header.Set("User-Agent", d.Agent)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return HTTPResponse{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTransportBytes+1))
	if err != nil {
		return HTTPResponse{StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > maxTransportBytes {
		return HTTPResponse{StatusCode: resp.StatusCode, Err: io.ErrUnexpectedEOF}
	}
	headers := make(map[string]string, len(resp.Header))
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	return HTTPResponse{StatusCode: resp.StatusCode, Body: body, Headers: headers}
}

// PostForm sends a form-urlencoded POST with optional extra headers.
func (d *DefaultHTTPClient) PostForm(ctx context.Context, rawURL string, fields url.Values, headers map[string]string) HTTPResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(fields.Encode()))
	if err != nil {
		return HTTPResponse{Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return d.do(ctx, req)
}

// Get sends a GET with the supplied headers.
func (d *DefaultHTTPClient) Get(ctx context.Context, rawURL string, headers map[string]string) HTTPResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HTTPResponse{Err: err}
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return d.do(ctx, req)
}

var _ HTTPClient = (*DefaultHTTPClient)(nil)

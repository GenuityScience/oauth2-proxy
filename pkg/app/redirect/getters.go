package redirect

import (
	"fmt"
	"net/http"

	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// redirectGetter represents a method to allow the proxy to determine a redirect
// based on the original request.
type redirectGetter func(req *http.Request) string

// getRdQuerystringRedirect handles this getAppRedirect strategy:
// - `rd` querysting parameter
func (a *appDirector) getRdQuerystringRedirect(req *http.Request) string {
	return a.validateRedirect(
		req.Form.Get("rd"),
		"Invalid redirect provided in rd querystring parameter: %s",
	)
}

// getXAuthRequestRedirect handles this getAppRedirect strategy:
// - `X-Auth-Request-Redirect` Header
func (a *appDirector) getXAuthRequestRedirect(req *http.Request) string {
	return a.validateRedirect(
		req.Header.Get("X-Auth-Request-Redirect"),
		"Invalid redirect provided in X-Auth-Request-Redirect header: %s",
	)
}

// getXForwardedHeadersRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-(Proto|Host|Prefix|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host|Prefix)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
func (a *appDirector) getXForwardedHeadersRedirect(req *http.Request) string {
	if !requestutil.IsForwardedRequest(req) {
		return ""
	}

	uri := requestutil.GetRequestURI(req)
	prefix := requestutil.GetRequestPrefix(req)
	if a.hasProxyPrefix(uri) {
		uri = prefix
	} else if prefix != "/" {
		uri = prefix + uri
	}

	redirect := fmt.Sprintf(
		"%s://%s%s",
		requestutil.GetRequestProto(req),
		requestutil.GetRequestHost(req),
		uri,
	)

	return a.validateRedirect(redirect,
		"Invalid redirect generated from X-Forwarded-* headers: %s")
}

// getURIRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `/`
func (a *appDirector) getURIRedirect(req *http.Request) string {
	redirect := a.validateRedirect(
		requestutil.GetRequestURI(req),
		"Invalid redirect generated from X-Forwarded-Uri header: %s",
	)
	if redirect == "" {
		redirect = req.URL.RequestURI()
	}

	if a.hasProxyPrefix(redirect) {
		return "/"
	}
	return redirect
}

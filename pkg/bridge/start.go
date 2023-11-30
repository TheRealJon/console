package bridge

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/klog"
)

func Start() {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	klog.InitFlags(fs)
	defer klog.Flush()
	b := NewBridge(fs)
	switch b.Listen.Scheme {
	case "http":
	case "https":
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-cert-file", b.TlsCertFile.String()))
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-key-file", b.TlsKeyFile.String()))
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("listen", "scheme must be one of: http, https"))
	}

	httpsrv := &http.Server{
		Addr:    b.Listen.Host,
		Handler: b.Server.HTTPHandler(),
		// Disable HTTP/2, which breaks WebSockets.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    crypto.SecureTLSConfig(&tls.Config{}),
	}

	if b.RedirectPort != 0 {
		go func() {
			// Listen on passed port number to be redirected to the console
			redirectServer := http.NewServeMux()
			redirectServer.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
				redirectURL := &flags.URL{
					Scheme:   b.Server.BaseURL.Scheme,
					Host:     b.Server.BaseURL.Host,
					RawQuery: req.URL.RawQuery,
					Path:     req.URL.Path,
				}
				http.Redirect(res, req, redirectURL.String(), http.StatusMovedPermanently)
			})
			redirectPort := fmt.Sprintf(":%d", b.RedirectPort)
			klog.Infof("Listening on %q for custom hostname redirect...", redirectPort)
			klog.Fatal(http.ListenAndServe(redirectPort, redirectServer))
		}()
	}

	klog.Infof("Binding to %s...", httpsrv.Addr)
	if b.Listen.Scheme == "https" {
		klog.Info("using TLS")
		klog.Fatal(httpsrv.ListenAndServeTLS(b.TlsCertFile.String(), b.TlsKeyFile.String()))
	} else {
		klog.Info("not using TLS")
		klog.Fatal(httpsrv.ListenAndServe())
	}
}

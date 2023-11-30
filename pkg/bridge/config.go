package bridge

import (
	"flag"
	"fmt"
	"os"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/serverconfig"
)

func (b *Bridge) applyConfig(fs *flag.FlagSet) {
	cfg, err := serverconfig.Parse(fs, os.Args[1:], "BRIDGE")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	err = serverconfig.Validate(fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	b.AuthOptions.ApplyConfig(&cfg.Auth)
	switch b.Listen.Scheme {
	case "http":
	case "https":
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-cert-file", b.TlsCertFile.String()))
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-key-file", b.TlsKeyFile.String()))
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("listen", "scheme must be one of: http, https"))
	}
}

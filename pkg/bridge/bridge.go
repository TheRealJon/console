package bridge

import (
	"flag"
)

func NewBridge(fs *flag.FlagSet) *Bridge {
	b := &Bridge{}
	b.addFlags(fs)
	b.AuthOptions = NewAuthOptions()
	b.AuthOptions.AddFlags(fs)
	b.applyConfig(fs)
	b.buildServer()
	return b
}

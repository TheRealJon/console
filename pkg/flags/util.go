package flags

import "flag"

func SetFlagIfEmpty(flag flag.Value, value string) {
	if flag.String() == "" {
		flag.Set(value)
	}
}

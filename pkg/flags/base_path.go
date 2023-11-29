package flags

import (
	"fmt"
	"strings"
)

type BasePath string

func (b *BasePath) String() string {
	return string(*b)
}

func (b *BasePath) Set(value string) error {
	if !strings.HasPrefix(value, "/") || !strings.HasSuffix(value, "/") {
		return fmt.Errorf("value must start and end with a forward slash")
	}
	*b = BasePath(value)
	return nil
}

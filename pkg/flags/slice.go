package flags

import (
	"fmt"
	"strings"
)

// Slightly modified version of StringSliceFlag from github.com/coreos/pkg/flagutil.
// Slice parses a comma-delimited list of strings into a []string slice. This implememtation
// fails if an empty string is encountered when parsing the slice from a string. This type
// implements the flag.Value interface.
type Slice []string

func (s *Slice) String() string {
	return fmt.Sprintf("%+v", *s)
}

func (s *Slice) Set(v string) error {
	var val []string
	split := strings.Split(v, ",")
	for _, s := range split {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("Empty string encountered while parsing list: %s", v)
		}
		val = append(val, s)
	}
	*s = val
	return nil
}

func (s *Slice) Get() []string {
	return []string(*s)
}

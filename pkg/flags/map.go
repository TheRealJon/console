package flags

import (
	"fmt"
	"sort"
	"strings"
)

// Map is used for defining a set of key-value pairs on a single flag, eg.:
// ... --plugins plugin-name=plugin-endpoint, plugin-name2=plugin-endpoint2
type Map map[string]string

func (mf *Map) String() string {
	keyValuePairs := []string{}
	for k, v := range *mf {
		keyValuePairs = append(keyValuePairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(keyValuePairs)
	return strings.Join(keyValuePairs, ", ")
}

func (mf *Map) Set(value string) error {
	keyValuePairs := strings.Split(value, ",")
	for _, keyValuePair := range keyValuePairs {
		keyValuePair = strings.TrimSpace(keyValuePair)
		if len(keyValuePair) == 0 {
			continue
		}
		splitted := strings.SplitN(keyValuePair, "=", 2)
		if len(splitted) != 2 {
			return fmt.Errorf("invalid key value pair %s", keyValuePair)
		}
		(*mf)[splitted[0]] = splitted[1]
	}
	return nil
}

func (smf *Map) Get() map[string]string {
	return map[string]string(*smf)
}

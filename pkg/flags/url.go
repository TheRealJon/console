package flags

import (
	"fmt"
	"net/url"
)

type URL url.URL

func (u *URL) String() string {
	if u == nil {
		return ""
	}
	return (*url.URL)(u).String()
}

func (u *URL) Set(v string) error {
	if len(v) == 0 {
		*u = URL(url.URL{})
		return nil
	}

	ur, err := url.Parse(v)
	if err != nil {
		return err
	}

	if ur == nil || ur.String() == "" || ur.Scheme == "" || ur.Host == "" {
		return fmt.Errorf("malformed URL: %s", v)
	}
	*u = URL(*ur)
	return nil
}

func (u *URL) Get() *url.URL {
	if u == nil {
		return nil
	}
	return (*url.URL)(u)
}

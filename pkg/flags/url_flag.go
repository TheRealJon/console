package flags

import (
	"fmt"
	"net/url"
)

type URLFlag url.URL

func (u *URLFlag) String() string {
	if u == nil {
		return ""
	}
	return (*url.URL)(u).String()
}

func (u *URLFlag) Set(v string) error {
	if len(v) == 0 {
		*u = URLFlag(url.URL{})
		return nil
	}

	ur, err := url.Parse(v)
	if err != nil {
		return err
	}

	if ur == nil || ur.String() == "" || ur.Scheme == "" || ur.Host == "" {
		return fmt.Errorf("malformed URL: %s", v)
	}
	*u = URLFlag(*ur)
	return nil
}

func (u *URLFlag) Get() *url.URL {
	if u == nil {
		return nil
	}
	return (*url.URL)(u)
}

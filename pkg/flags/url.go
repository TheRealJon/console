package flags

import (
	"fmt"
	"net/url"
	"strings"
)

type URL url.URL

func (u *URL) String() string {
	if u == nil {
		return ""
	}
	return (*url.URL)(u).String()
}

func (u *URL) Set(v string) error {
	ur, err := parseURL(v)
	if err != nil {
		return err
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

type URLWithTrailingSlash URL

func (u *URLWithTrailingSlash) String() string {
	if u == nil {
		return ""
	}
	return (*url.URL)(u).String()
}

func (u *URLWithTrailingSlash) Set(value string) error {
	if !strings.HasSuffix(value, "/") {
		return fmt.Errorf("URL must end with a slash")
	}
	ur, err := parseURL(value)
	if err != nil {
		return err
	}
	*u = URLWithTrailingSlash(*ur)
	return nil
}

func (u *URLWithTrailingSlash) Get() *url.URL {
	if u == nil {
		return nil
	}
	return (*url.URL)(u)
}

func parseURL(value string) (*url.URL, error) {
	if len(value) == 0 {
		return &url.URL{}, nil
	}

	ur, err := url.Parse(value)
	if err != nil {
		return nil, err
	}

	if ur == nil || ur.String() == "" || ur.Scheme == "" || ur.Host == "" {
		return nil, fmt.Errorf("malformed URL: %s", value)
	}
	return ur, nil
}

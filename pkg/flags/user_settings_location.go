package flags

import "fmt"

type UserSettingsLocation string

const (
	UserSettingsLocationConfigMap    UserSettingsLocation = "configmap"
	UserSettingsLocationLocalStorage UserSettingsLocation = "local-storage"
)

func (u UserSettingsLocation) String() string {
	return string(u)
}

func (u *UserSettingsLocation) Set(value string) error {
	switch value {
	case string(UserSettingsLocationConfigMap):
	case string(UserSettingsLocationLocalStorage):
	default:
		return fmt.Errorf("UserSettingsLocation %s is not valid; valid options are configmap or local-storage", value)
	}
	*u = UserSettingsLocation(value)
	return nil
}

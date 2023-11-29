package flags

import "fmt"

type AuthType string

const (
	AuthTypeDisabled  AuthType = "disabled"
	AuthTypeOIDC      AuthType = "oidc"
	AuthTypeOpenShift AuthType = "openshift"
)

func (a *AuthType) String() string {
	return string(*a)
}

func (a *AuthType) Set(value string) error {
	switch value {
	case string(AuthTypeDisabled):
	case string(AuthTypeOIDC):
	case string(AuthTypeOpenShift):
	default:
		return fmt.Errorf("AuthType %s is not valid; valid options are disabled, oidc, or openshift", value)
	}
	*a = AuthType(value)
	return nil
}

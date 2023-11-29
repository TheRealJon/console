package flags

import "fmt"

type K8sAuth string

const (
	K8sAuthServiceAccount K8sAuth = "service-account"
	K8sAuthBearerToken    K8sAuth = "bearer-token"
	K8sAuthOIDC           K8sAuth = "oidc"
	K8sAuthOpenShift      K8sAuth = "openshift"
)

func (k K8sAuth) String() string {
	return string(k)
}

func (k *K8sAuth) Set(value string) error {
	switch value {
	case string(K8sAuthServiceAccount):
	case string(K8sAuthBearerToken):
	case string(K8sAuthOIDC):
	case string(K8sAuthOpenShift):
	default:
		return fmt.Errorf("K8sAuth %s is not valid; valid options are service-account, bearer-token, oidc, or openshift", value)
	}
	*k = K8sAuth(value)
	return nil
}

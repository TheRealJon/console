package flags

import (
	"fmt"

	"k8s.io/klog"
)

type Brand string

const (
	BrandAzure     Brand = "azure"
	BrandDedicated Brand = "dedicated"
	BrandOCP       Brand = "ocp"
	BrandOKD       Brand = "okd"
	BrandOnline    Brand = "online"
	BrandOpenShift Brand = "openshift"
	BrandOrigin    Brand = "origin"
	BrandROSA      Brand = "rosa"
)

func (b *Brand) String() string {
	return string(*b)
}

func (b *Brand) Set(value string) error {
	if value == "origin" {
		klog.Warningf("DEPRECATED: brand 'origin' is deprecated, use 'okd' instead")
		*b = BrandOKD
		return nil
	}

	switch value {
	case "azure":
	case "dedicated":
	case "ocp":
	case "okd":
	case "online":
	case "openshift":
	case "rosa":
	default:
		return fmt.Errorf("value must be one of azure, dedicated, ocp, okd, online, openshift, or rosa.")
	}
	*b = Brand(value)
	return nil
}

func (b *Brand) Validate(value string) error {

	return nil
}

package flags

import "fmt"

type ControlPlaneTopology string

const (
	ControlPlaneTopologyExternal       ControlPlaneTopology = "External"
	ControlPlanTopologyHighlyAvailable ControlPlaneTopology = "HighlyAvailable"
	ControlPlaneTopologySingleReplica  ControlPlaneTopology = "SingleReplica"
)

func (c ControlPlaneTopology) String() string {
	return string(c)
}

func (c *ControlPlaneTopology) Set(value string) error {
	switch ControlPlaneTopology(value) {
	case ControlPlaneTopologyExternal:
	case ControlPlanTopologyHighlyAvailable:
	case ControlPlaneTopologySingleReplica:
	default:
		return fmt.Errorf("invalid value %q. Must be one of External, HighlyAvailable, or SingleReplica", value)
	}
	*c = ControlPlaneTopology(value)
	return nil
}

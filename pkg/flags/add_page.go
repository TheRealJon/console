package flags

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openshift/console/pkg/api"
)

type AddPage string

func (a *AddPage) String() string {
	return string(*a)
}

func (a *AddPage) Set(value string) error {
	err := a.Validate(value)
	if err != nil {
		return err
	}
	*a = AddPage(value)
	return nil
}

func (f *AddPage) Validate(value string) error {
	if value == "" {
		return nil
	}
	var addPage api.AddPage
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&addPage); err != nil {
		return err
	}

	for index, action := range addPage.DisabledActions {
		if action == "" {
			return fmt.Errorf("Add page disabled action at index %d must not be empty.", index)
		}
	}
	return nil
}

package flags

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openshift/console/pkg/api"
)

type DeveloperCatalogCategories string

func (d *DeveloperCatalogCategories) String() string {
	return string(*d)
}

func (d *DeveloperCatalogCategories) Set(value string) error {
	err := d.Validate(value)
	if err != nil {
		return err
	}
	*d = DeveloperCatalogCategories(value)
	return nil
}

func (d *DeveloperCatalogCategories) Validate(value string) error {
	if value == "" {
		return nil
	}
	var developerCatalogCategories []api.DeveloperConsoleCatalogCategory
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&developerCatalogCategories); err != nil {
		return err
	}
	for index, category := range developerCatalogCategories {
		if category.ID == "" || category.Label == "" {
			return fmt.Errorf("Developer catalog category at index %d must have at least id and label properties.", index)
		}
		for subcategoryIndex, subcategory := range category.Subcategories {
			if subcategory.ID == "" || subcategory.Label == "" {
				return fmt.Errorf("Developer catalog subcategory at index %d of category \"%s\" must have at least id and label properties.", subcategoryIndex, category.ID)
			}
		}
	}
	*d = DeveloperCatalogCategories(value)
	return nil
}

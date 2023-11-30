package flags

import "testing"

func TestValidEmptyDeveloperCatalogCategories(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("")
	if err != nil {
		t.Error("Unexpected error when parsing an empty string.", err)
	}
	if d != "" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, "")
	}
}

func TestValidEmptyArrayForDeveloperCatalogCategories(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("[]")
	if err != nil {
		t.Error("Unexpected error when parsing an empty array.", err)
	}
	if d != "[]" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, nil)
	}
}

func TestValidDeveloperCatalogCategories(t *testing.T) {
	var d DeveloperCatalogCategories
	testValue := "[{ \"id\": \"java\", \"label\": \"Java\", \"tags\": [ \"jvm\", \"java\", \"quarkus\" ] }]"
	err := d.Set(testValue)
	if err != nil {
		t.Errorf("Unexpected error when parsing valid developer catalog categories: %v.", err)
	}
	if d.String() != testValue {
		t.Errorf("Unexpected value: actual %v, expected %v", d, nil)
	}
}

func TestInvalidObjectForDeveloperCatalogCategories(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("{}")
	if err == nil {
		t.Error("Expected an error when parsing an object.")
	}
	if d != "" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, "")
	}
}

func TestIncompleteDeveloperCatalogCategory(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("[{}]")
	actualMsg := err.Error()
	expectedMsg := "Developer catalog category at index 0 must have at least id and label properties."
	if actualMsg != expectedMsg {
		t.Errorf("Unexpected error: actual\n%s\n, expected\n%s", actualMsg, expectedMsg)
	}
	if d != "" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, "")
	}
}

func TestIncompleteDeveloperCatalogSubcategory(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("[{ \"id\": \"java\", \"label\": \"Java\", \"tags\": [ \"jvm\", \"java\", \"quarkus\" ], \"subcategories\": [ {} ] }]")
	actualMsg := err.Error()
	expectedMsg := "Developer catalog subcategory at index 0 of category \"java\" must have at least id and label properties."
	if actualMsg != expectedMsg {
		t.Errorf("Unexpected error: actual\n%s\n, expected\n%s", actualMsg, expectedMsg)
	}
	if d != "" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, "")
	}
}

func TestUnknownPropertyInDeveloperCatalogCategory(t *testing.T) {
	var d DeveloperCatalogCategories
	err := d.Set("[{ \"unknown key\": \"ignored value\" }]")
	actualMsg := err.Error()
	expectedMsg := "json: unknown field \"unknown key\""
	if actualMsg != expectedMsg {
		t.Errorf("Unexpected error: actual\n%s\n, expected\n%s", actualMsg, expectedMsg)
	}
	if d != "" {
		t.Errorf("Unexpected value: actual %v, expected %v", d, "")
	}
}

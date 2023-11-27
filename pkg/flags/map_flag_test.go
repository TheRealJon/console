package flags

import (
	"reflect"
	"testing"
)

func TestMapFlagSetter(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      MapFlag
		expectedError error
	}{
		{
			name:          "Should ignore an empty string",
			input:         "",
			expected:      MapFlag{},
			expectedError: nil,
		},
		{
			name:  "Should accept and split key=value pair",
			input: "key=value",
			expected: MapFlag{
				"key": "value",
			},
			expectedError: nil,
		},
		{
			name:  "Should accept multiple comma-separated key=value pairs",
			input: "key1=value1,key2=value2",
			expected: MapFlag{
				"key1": "value1",
				"key2": "value2",
			},
			expectedError: nil,
		},
		{
			name:  "Should automatically trim spaces between key=value pairs",
			input: "key1=value1, key2=value2, ",
			expected: MapFlag{
				"key1": "value1",
				"key2": "value2",
			},
			expectedError: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := MapFlag{}
			actualError := actual.Set(test.input)
			if !reflect.DeepEqual(test.expected, actual) {
				t.Errorf("Data does not match expectation:\n%v\nbut got\n%v", test.expected, actual)
			}
			if test.expectedError == nil && actualError != nil {
				t.Errorf("Error does not match expectation:\n%v\nbut got\n%v", test.expectedError, actualError)
			} else if test.expectedError != nil && (actualError == nil || test.expectedError.Error() != actualError.Error()) {
				t.Errorf("Error does not match expectation:\n%v\nbut got\n%v", test.expectedError, actualError)
			}
		})
	}
}

// Set is called multiple times when parsing the config file
func TestCallingMapFlagSetterMultipleTimes(t *testing.T) {
	actual := MapFlag{}
	actual.Set("plugin-a=Service1")
	actual.Set("plugin-b=Service2 ")
	actual.Set("plugin-c=Service3, plugin-d=Service4, ")
	expected := MapFlag{
		"plugin-a": "Service1",
		"plugin-b": "Service2",
		"plugin-c": "Service3",
		"plugin-d": "Service4",
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Data does not match expectation:\n%v\nbut got\n%v", expected, actual)
	}
}

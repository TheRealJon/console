package flags

import (
	"errors"
	"testing"
)

func TestValidAddPage(t *testing.T) {
	tests := []struct {
		testcase      string
		input         string
		expectedValue string
		expectedError error
	}{
		{
			testcase:      "empty data",
			input:         "",
			expectedValue: "",
			expectedError: nil,
		},
		{
			testcase:      "invalid json",
			input:         "invalid json",
			expectedValue: "",
			expectedError: errors.New("invalid character 'i' looking for beginning of value"),
		},
		{
			testcase:      "empty disabled action",
			input:         "{ \"disabledActions\": [\"\"] }",
			expectedValue: "",
			expectedError: errors.New("Add page disabled action at index 0 must not be empty."),
		},
		{
			testcase:      "two valid disabled actions",
			input:         "{ \"disabledActions\": [ \"action1\", \"action2\" ] }",
			expectedValue: "{ \"disabledActions\": [ \"action1\", \"action2\" ] }",
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.testcase, func(t *testing.T) {
			var addPageFlag AddPage
			actualError := addPageFlag.Set(test.input)
			if addPageFlag.String() != test.expectedValue {
				t.Errorf("Unexpected value: actual %v, expected %v", addPageFlag.String(), test.input)
			}
			if test.expectedError == nil && actualError != nil {
				t.Errorf("Error does not match expectation:\n%v\nbut got\n%v", test.expectedError, actualError)
			} else if test.expectedError != nil && (actualError == nil || test.expectedError.Error() != actualError.Error()) {
				t.Errorf("Error does not match expectation:\n%v\nbut got\n%v", test.expectedError, actualError)
			}
		})
	}
}

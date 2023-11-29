package flags

import (
	"os"
)

type File string

func (f *File) String() string {
	return string(*f)
}

func (f *File) Set(value string) error {
	if value != "" {
		_, err := os.Stat(value)
		if err != nil {
			return err
		}
	}
	*f = File(value)
	return nil
}

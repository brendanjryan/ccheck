package parsers

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ghodss/yaml"
)

// Parser is the interface implemented by objects that can unmarshal
// bytes into a golang interface.
type Parser = func([]byte, interface{}) error

func Get(fileName string) (Parser, error) {
	suffix := filepath.Ext(fileName)

	switch suffix {
	case ".yaml", ".yml", ".json":
		return parseYAML, nil

		// TODO (brendanjryan) add more parsers
	default:
		return nil, errors.New("unable to find Parser for file: " + fileName)
	}
}

func parseYAML(bs []byte, v interface{}) error {
	err := yaml.Unmarshal(bs, v)
	if err != nil {
		return fmt.Errorf("unable to parse yaml: %s", err)
	}

	return nil
}

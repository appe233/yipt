package parser

import (
	"os"

	"gopkg.in/yaml.v3"
	"yipt/internal/ast"
)

// ParseFile reads a YAML file and returns the parsed Document.
func ParseFile(path string) (*ast.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc ast.Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

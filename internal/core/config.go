package core

import (
	"github.com/pelletier/go-toml/v2"
	"path/filepath"
	"strings"
)

type ArtifactConfig struct {
	Root string `toml:"root" json:"root,omitempty"`
}
type Config struct {
	Clouds    map[Cloud]Binding `toml:"clouds" json:"clouds"`
	Artifacts ArtifactConfig    `toml:"artifacts" json:"artifacts"`
}

func ParseConfig(input string) (Config, error) {
	var config Config
	decoder := toml.NewDecoder(strings.NewReader(input)).DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, detail("invalid_request", "invalid TOML configuration: %s", err)
	}
	return config, config.Validate()
}
func (config *Config) Validate() error {
	if config.Clouds == nil {
		config.Clouds = map[Cloud]Binding{}
	}
	if config.Artifacts.Root != "" && !filepath.IsAbs(config.Artifacts.Root) {
		return Fail("invalid_request", "artifact root must be an absolute path")
	}
	for cloud, binding := range config.Clouds {
		if _, err := ParseCloud(string(cloud)); err != nil {
			return err
		}
		if err := binding.Validate(); err != nil {
			return err
		}
		config.Clouds[cloud] = binding
	}
	return nil
}

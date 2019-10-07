package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type config struct {
	BagPath       string `yaml:"bag_path"`
	Mountpoint    string `yaml:"mountpoint"`
	MountTimeout  int    `yaml:"mount_timeout"`
	Debug         bool   `yaml:"debug"`
	PrivateRSAKey string `yaml:"private_rsa_key"`
	PublicRSAKey  string `yaml:"public_rsa_key"`
}

func NewConfig(path string) (config, error) {
	c := defaults()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("Could not read file %s: %s", path, err.Error())
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return c, fmt.Errorf("Could not read data from config file %s: %s", path, err.Error())
	}

	c.BagPath = tidyPath(c.BagPath)
	c.Mountpoint = tidyPath(c.Mountpoint)
	c.PrivateRSAKey = tidyPath(c.PrivateRSAKey)
	c.PublicRSAKey = tidyPath(c.PublicRSAKey)

	return c, nil
}

func defaults() config {
	return config{
		BagPath:       os.ExpandEnv("$HOME/.scumbag/"),
		Mountpoint:    os.ExpandEnv("$HOME/.scum/"),
		MountTimeout:  120,
		Debug:         false,
		PrivateRSAKey: "$HOME/.ssh/id_rsa",
		PublicRSAKey:  "$HOME/.ssh/id_rsa.pub",
	}
}

func tidyPath(path string) string {
	path = strings.ReplaceAll(path, "~", "$HOME")
	path = os.ExpandEnv(path)
	return path
}

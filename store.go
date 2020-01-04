package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

const bagNameSeparator = "_"

type Bag struct {
	Base string
}

func NewBag(path string) (Bag, error) {
	b := Bag{}
	stat, err := os.Stat(path)
	if err != nil {
		return b, fmt.Errorf("scum bag '%s' could not be openend: %s", path, err.Error())
	}

	if !stat.IsDir() {
		return b, fmt.Errorf("scum bag '%s' is not a Directory", path)
	}

	b.Base = path
	return b, nil
}

func (b Bag) List(filters []string) (map[string]string, error) {
	if len(filters) == 0 {
		filters = append(filters, ".*")
	}
	out := map[string]string{}

	files, err := ioutil.ReadDir(b.Base)
	if err != nil {
		return out, fmt.Errorf("scum bag '%s' could not be listed: %s", b.Base, err.Error())
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		seg := strings.SplitN(file.Name(), bagNameSeparator, 2)
		if len(seg) < 2 {
			return out, fmt.Errorf("scum bag '%s' contains malformed file: %s", b.Base, file.Name())
		}

		kind := seg[0]
		name := seg[1]
		for _, filter := range filters {
			if matched, _ := regexp.MatchString(filter, name); matched {
				out[name] = kind
			}
		}
	}

	return out, nil
}

func (b Bag) Read(name, kind string) ([]byte, error) {
	path := path.Join(b.Base, fmt.Sprintf("%s%s%s", kind, bagNameSeparator, name))
	return ioutil.ReadFile(path)
}

func (b Bag) Write(name, kind string, data []byte) error {
	path := path.Join(b.Base, fmt.Sprintf("%s%s%s", kind, bagNameSeparator, name))
	return ioutil.WriteFile(path, data, 0600)
}

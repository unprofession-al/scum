package main

import (
	"fmt"
	"strings"
	"sync"
)

var (
	ptrMu sync.Mutex
	ptr   = ProfileTypeRegistry{}
)

type ProfileTypeRegistry map[string]func() Profile

func (p ProfileTypeRegistry) List() []string {
	out := []string{}
	for name := range p {
		out = append(out, name)
	}
	return out
}

func (p ProfileTypeRegistry) Describe(name string) (string, error) {
	var out string

	profile, err := NewProfile(name)
	if err != nil {
		return out, err
	}

	d := profile.Describe()
	c := profile.Capabilities()
	out = fmt.Sprintf("%s\nCapabilities:\n%s", d, c.String())

	return out, nil
}

func RegisterProfileType(kind string, empty func() Profile) {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	if _, dup := ptr[kind]; dup {
		panic("Register called twice for pofile type " + kind)
	}
	ptr[kind] = empty
}

func NewProfile(kind string) (Profile, error) {
	empty, ok := ptr[kind]
	if !ok {
		kinds := []string{}
		for k, _ := range ptr {
			kinds = append(kinds, k)
		}
		return nil, fmt.Errorf("Profile type '%s' does not exist, must be one of the following: %s", kind, strings.Join(kinds, ", "))
	}
	return empty(), nil
}

type Profile interface {
	Describe() string
	Capabilities() ProfileCapabilities
	Prompt() error
	Serialize() ([]byte, error)
	Deserialize([]byte) error
	SetName(string)
	Name() string
	String() string
	Type() string
	MountSnippet() (string, string)
	RotateCredentials() ([]byte, error)
	VerifyCredentials() (string, bool)
}

type ProfileCapabilities struct {
	Mount  bool
	Env    bool
	Rotate bool
	Import bool
	Verify bool
}

func (c ProfileCapabilities) String() string {
	getUnicode := func(b bool) string {
		if b {
			return "✔"
		}
		return "✘"
	}
	var out []string
	out = append(out, fmt.Sprintf("\t%s\tAllows to mount standard credentials file", getUnicode(c.Mount)))
	out = append(out, fmt.Sprintf("\t%s\tAllows to print credentials as environment variables", getUnicode(c.Env)))
	out = append(out, fmt.Sprintf("\t%s\tAllows to rotate credentials", getUnicode(c.Rotate)))
	out = append(out, fmt.Sprintf("\t%s\tAllows to import credentials from a file", getUnicode(c.Import)))
	out = append(out, fmt.Sprintf("\t%s\tAllows to verify credentials", getUnicode(c.Verify)))
	return strings.Join(out, "\n")
}

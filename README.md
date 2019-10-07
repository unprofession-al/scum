# Secret Credential Utility/Manager

DISCLAIMER: This is a personal proof of concept. Please do not use this...

Many CLI tools used to work with API's use some kind of credentials file to store secrets. Usually these secrets are unencrypted
and must therefore be managed very carefully.

`scum` encrypts those secrets with your SSH keys (everybody has some of those). It allows you to perform common maintenance
operations such as _key rotation_ or _key locking_.

It also allows you to mount a pseudo file system containing (a subset of) your credentials for a short period of time.

## Installation

### From soucre: 

Make sure you have [go](https://golang.org/doc/install) installed, then run:

```
go get -u github.com/unprofession-al/scum
```

### Usage

```
# scum
Secret Credentials Utility/Manager

Usage:
  scum [command]

Available Commands:
  add         Add a new set of credential
  config      Print configuration
  help        Help about any command
  list        List credential
  mount       Mount a set of credential
  rotate      Rotate credential
  show        Show set of credential
  types       Show information about the supported credential types
  verify      Verify a set of credential

Flags:
  -c, --config string   Configuration file for scum (default "/home/daniel/.config/scum/config.yml")
  -h, --help            help for scum

Use "scum [command] --help" for more information about a command.
```

## Configure

To customize the configuration run:

```
mkdir -p ~/.config/scum
scum config > ~/.config/scum/config.yml
vim ~/.config/scum/config.yml
```

Delete the lines you are happy with (means you accept the defaults) and change the lines you don't like,


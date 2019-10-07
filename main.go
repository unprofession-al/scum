package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

var (
	configPath string
	flagKind   string
	cfg        config
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", os.ExpandEnv("$HOME/.config/scum/config.yml"), "Configuration file for scum")

	rootCmd.AddCommand(typesCmd)

	rootCmd.AddCommand(listCmd)

	addCmd.PersistentFlags().StringVarP(&flagKind, "type", "t", "aws", "Profile type")
	rootCmd.AddCommand(addCmd)

	rootCmd.AddCommand(showCmd)

	rootCmd.AddCommand(mountCmd)

	rootCmd.AddCommand(configCmd)
	var err error
	cfg, err = NewConfig(configPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "scum",
	Short: "Secret Credentials Utility/Manager",
}

var typesCmd = &cobra.Command{
	Use:   "types",
	Short: "Show information about the credential types",
	Run: func(cmd *cobra.Command, args []string) {
		for _, name := range ptr.List() {
			d, err := ptr.Describe(name)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}
			fmt.Printf("Profile Type \033[1m'%s'\033[0m\n\n", name)
			fmt.Printf("%s\n\n", d)
		}
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print configuration",
	Run: func(cmd *cobra.Command, args []string) {
		d, err := yaml.Marshal(&cfg)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("---\n%s\n", string(d))
	},
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new set of credential",
	Run: func(cmd *cobra.Command, args []string) {
		c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		p, err := NewProfile(flagKind)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		p.Prompt()
		serialized, err := p.Serialize()
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		encrypted, err := c.Encrypt(serialized)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		b, err := NewBag(cfg.BagPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		err = b.Write(p.Name(), p.Type(), encrypted)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential",
	Run: func(cmd *cobra.Command, args []string) {
		b, err := NewBag(cfg.BagPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		list, err := b.List(args)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		if len(list) == 0 {
			fmt.Println("No matches found")
		}

		for name, kind := range list {
			fmt.Printf("%s (type %s)\n", name, kind)
		}
	},
}
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show set of credential",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		b, err := NewBag(cfg.BagPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		list, err := b.List(args)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		var pw []byte
		if len(list) > 0 {
			fmt.Fprintf(os.Stderr, "Enter Password: ")
			pw, err = terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}
			fmt.Println("")
		} else {
			fmt.Println("No matches found")
		}

		for name, kind := range list {
			p, err := NewProfile(kind)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			encrypted, err := b.Read(name, kind)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			data, err := c.Decrypt(encrypted, pw)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			err = p.Deserialize(data)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			fmt.Println(p)

		}
	},
}

var mountCmd = &cobra.Command{
	Use:   "mount",
	Short: "Mount a set of credential",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		b, err := NewBag(cfg.BagPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		list, err := b.List(args)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		var pw []byte
		if len(list) > 0 {
			fmt.Fprintf(os.Stderr, "Enter Password: ")
			pw, err = terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}
			fmt.Println("")
		} else {
			fmt.Println("No matches found")
		}

		mountFiles := map[string][]byte{}
		for name, kind := range list {
			p, err := NewProfile(kind)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			if !p.Capabilities().Mount {
				fmt.Printf("Profile '%s' cannot be mounted because its of kind %s which does not support mount. Skipping...", name, kind)
				continue
			}

			encrypted, err := b.Read(name, kind)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			data, err := c.Decrypt(encrypted, pw)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			err = p.Deserialize(data)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			mountPath, mountSnippet := p.MountSnippet()
			mountData := append(mountFiles[mountPath], []byte(mountSnippet)...)
			mountFiles[mountPath] = mountData
		}
		mount(cfg.Mountpoint, mountFiles, cfg.MountTimeout, cfg.Debug)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

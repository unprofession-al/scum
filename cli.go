package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

type App struct {
	cfg struct {
		configPath   string
		flagKind     string
		mountTimeout int
	}

	// entry point
	Execute func() error
}

func NewApp() *App {
	a := &App{}

	// root
	rootCmd := &cobra.Command{
		Use:   "scum",
		Short: "Secret Credentials Utility/Manager",
	}
	rootCmd.PersistentFlags().StringVarP(&a.cfg.configPath, "config", "c", os.ExpandEnv("$HOME/.config/scum/config.yml"), "Configuration file for scum")
	a.Execute = rootCmd.Execute

	// types
	typesCmd := &cobra.Command{
		Use:   "types",
		Short: "Show information about the supported credential types",
		Run:   a.typesCmd,
	}
	rootCmd.AddCommand(typesCmd)

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List credential",
		Run:   a.listCmd,
	}
	rootCmd.AddCommand(listCmd)

	// add
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new set of credential",
		Run:   a.addCmd,
	}
	addCmd.PersistentFlags().StringVarP(&a.cfg.flagKind, "type", "t", "aws", "Profile type")
	rootCmd.AddCommand(addCmd)

	// edit
	editCmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit a new set of credential in $EDITOR",
		Run:   a.editCmd,
	}
	rootCmd.AddCommand(editCmd)

	// show
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show set of credential",
		Args:  cobra.MinimumNArgs(1),
		Run:   a.showCmd,
	}
	rootCmd.AddCommand(showCmd)

	// mount
	mountCmd := &cobra.Command{
		Use:   "mount",
		Short: "Mount a set of credential",
		Args:  cobra.MinimumNArgs(1),
		Run:   a.mountCmd,
	}
	mountCmd.PersistentFlags().IntVar(&a.cfg.mountTimeout, "timeout", a.cfg.mountTimeout, "Timeout of the mount in seconds")
	rootCmd.AddCommand(mountCmd)

	// rotate
	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate credential",
		Args:  cobra.MinimumNArgs(1),
		Run:   a.rotateCmd,
	}
	rootCmd.AddCommand(rotateCmd)

	// verify
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a set of credential",
		Args:  cobra.MinimumNArgs(1),
		Run:   a.verifyCmd,
	}
	rootCmd.AddCommand(verifyCmd)

	// config
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Print configuration",
		Run:   a.configCmd,
	}
	rootCmd.AddCommand(configCmd)

	// version
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version info",
		Run:   a.versionCmd,
	}
	rootCmd.AddCommand(versionCmd)

	return a
}

func (a *App) typesCmd(cmd *cobra.Command, args []string) {
	for _, name := range ptr.List() {
		d, err := ptr.Describe(name)
		exitOnErr(err)
		fmt.Printf("Profile Type \033[1m'%s'\033[0m\n\n", name)
		fmt.Printf("%s\n\n", d)
	}
}

func (a *App) configCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	d, err := yaml.Marshal(&cfg)
	exitOnErr(err)
	fmt.Printf("---\n%s\n", string(d))
}

func (a *App) addCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	p, err := NewProfile(a.cfg.flagKind)
	exitOnErr(err)

	p.Prompt()
	serialized, err := p.Serialize()
	exitOnErr(err)

	encrypted, err := c.Encrypt(serialized)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	err = b.Write(p.Name(), p.Type(), encrypted)
	exitOnErr(err)
}

func (a *App) listCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	if len(list) == 0 {
		fmt.Println("No matches found")
	}

	for name, kind := range list {
		fmt.Printf("%s (type %s)\n", name, kind)
	}
}

func (a *App) showCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	var pw []byte
	if len(list) > 0 {
		pw, err = promptPassword(cfg.PrivateRSAKey, os.Stderr)
		exitOnErr(err)
	} else {
		fmt.Println("No matches found")
		return
	}

	for name, kind := range list {
		p, err := NewProfile(kind)
		exitOnErr(err)

		encrypted, err := b.Read(name, kind)
		exitOnErr(err)

		data, err := c.Decrypt(encrypted, pw)
		exitOnErr(err)

		err = p.Deserialize(data)
		exitOnErr(err)

		fmt.Println(p)
	}
}

func (a *App) editCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	var pw []byte
	if len(list) > 0 {
		pw, err = promptPassword(cfg.PrivateRSAKey, os.Stderr)
		exitOnErr(err)
	} else {
		fmt.Println("No matches found")
		return
	}

	for name, kind := range list {
		encrypted, err := b.Read(name, kind)
		exitOnErr(err)

		data, err := c.Decrypt(encrypted, pw)
		exitOnErr(err)

		edited, err := CaptureInputFromEditor(data)
		exitOnErr(err)

		newEncrypted, err := c.Encrypt(edited)
		exitOnErr(err)

		err = b.Write(name, kind, newEncrypted)
		exitOnErr(err)

		fmt.Printf("done!\n")
	}
}

func (a *App) mountCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	var pw []byte
	if len(list) > 0 {
		pw, err = promptPassword(cfg.PrivateRSAKey, os.Stderr)
		exitOnErr(err)
	} else {
		fmt.Println("No matches found")
		return
	}

	mountFiles := map[string][]byte{}
	for name, kind := range list {
		p, err := NewProfile(kind)
		exitOnErr(err)

		if !p.Capabilities().Mount {
			fmt.Printf("Profile '%s' cannot be mounted because its of kind %s which does not support mount. Skipping...\n", name, kind)
			continue
		}

		encrypted, err := b.Read(name, kind)
		exitOnErr(err)

		data, err := c.Decrypt(encrypted, pw)
		exitOnErr(err)

		err = p.Deserialize(data)
		exitOnErr(err)

		mountPath, mountSnippet := p.MountSnippet()
		mountData := append(mountFiles[mountPath], []byte(mountSnippet)...)
		mountFiles[mountPath] = mountData
	}

	fmt.Printf("Mounting credentials at %s\n", cfg.Mountpoint)
	mount(cfg.Mountpoint, mountFiles, a.cfg.mountTimeout, cfg.Debug)
}

func (a *App) verifyCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	var pw []byte
	if len(list) > 0 {
		pw, err = promptPassword(cfg.PrivateRSAKey, os.Stderr)
		exitOnErr(err)
	} else {
		fmt.Println("No matches found")
		return
	}

	for name, kind := range list {
		p, err := NewProfile(kind)
		exitOnErr(err)

		if !p.Capabilities().Verify {
			fmt.Printf("Profile '%s' cannot be verified because its of kind %s which does not support verification. Skipping...\n", name, kind)
			continue
		}

		encrypted, err := b.Read(name, kind)
		exitOnErr(err)

		data, err := c.Decrypt(encrypted, pw)
		exitOnErr(err)

		err = p.Deserialize(data)
		exitOnErr(err)

		getUnicode := func(b bool) string {
			if b {
				return "✔"
			}
			return "✘"
		}
		out, ok := p.VerifyCredentials()
		fmt.Printf("%s\t%s (type %s), message: %s\n", getUnicode(ok), p.Name(), p.Type(), out)
	}
}

func (a *App) rotateCmd(cmd *cobra.Command, args []string) {
	cfg, err := NewConfig(a.cfg.configPath)
	exitOnErr(err)

	c, err := NewCrypt(cfg.PublicRSAKey, cfg.PrivateRSAKey)
	exitOnErr(err)

	b, err := NewBag(cfg.BagPath)
	exitOnErr(err)

	list, err := b.List(args)
	exitOnErr(err)

	var pw []byte
	if len(list) > 0 {
		fmt.Printf("The following credentials are going to be rotated:\n")
		for name, kind := range list {
			fmt.Printf("\t%s (type %s)\n", name, kind)
		}
		pw, err = promptPassword(cfg.PrivateRSAKey, os.Stderr)
		exitOnErr(err)
	} else {
		fmt.Println("No matches found")
		return
	}

	for name, kind := range list {
		p, err := NewProfile(kind)
		exitOnErr(err)

		if !p.Capabilities().Rotate {
			fmt.Printf("Profile '%s' cannot be rotated because its of kind %s which does not support key rotation. Skipping...\n", name, kind)
			continue
		}
		fmt.Printf("Rotating %s (type %s)... ", name, p.Type())

		encrypted, err := b.Read(name, kind)
		exitOnErr(err)

		data, err := c.Decrypt(encrypted, pw)
		exitOnErr(err)

		err = p.Deserialize(data)
		exitOnErr(err)

		newSerialized, err := p.RotateCredentials()
		exitOnErr(err)

		newEncrypted, err := c.Encrypt(newSerialized)
		exitOnErr(err)

		err = b.Write(p.Name(), p.Type(), newEncrypted)
		exitOnErr(err)

		fmt.Printf("done!\n")
	}
}

func (a *App) versionCmd(cmd *cobra.Command, args []string) {
	fmt.Println(versionInfo())
}

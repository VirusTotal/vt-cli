package cmd

import (
	"fmt"
	"github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

func NewPrivilegeCmd(target string) *cobra.Command {
	cmd := &cobra.Command{
		Use: "privileges",
		Short: fmt.Sprintf("Change %s privileges", target),
	}

	cmd.AddCommand(NewPrivilegeGrantCmd(target))
	cmd.AddCommand(NewPrivilegeRevokeCmd(target))

	return cmd
}


type Privilege struct {
	Granted bool `json:"granted"`
}

type Privileges map[string]Privilege

func NewPrivilegeGrantCmd(target string) *cobra.Command {
	return &cobra.Command{
		Use: fmt.Sprintf("grant [%sname] [privilege]...", target),
		Short: fmt.Sprintf("Grant privileges to a %s", target),
		Example: fmt.Sprintf("  vt %s privileges grant my%s intelligence downloads-tier-2", target, target),
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			privileges := Privileges{}
			for _, arg := range args[1:] {
				privileges[arg] = Privilege{Granted: true}
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			obj := vt.NewObjectWithID(target, args[0])
			obj.Set("privileges", privileges)
			return client.PatchObject(vt.URL("%ss/%s", target, args[0]), obj)
		},
	}
}

func NewPrivilegeRevokeCmd(target string) *cobra.Command {
	return &cobra.Command{
		Use: fmt.Sprintf("revoke [%sname] [privilege]...", target),
		Short: fmt.Sprintf("Revoke privileges from a %s", target),
		Example: fmt.Sprintf("  vt %s privileges revoke my%s intelligence downloads-tier-2", target, target),
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			privileges := Privileges{}
			for _, arg := range args[1:] {
				privileges[arg] = Privilege{Granted: false}
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			obj := vt.NewObjectWithID(target, args[0])
			obj.Set("privileges", privileges)
			return client.PatchObject(vt.URL("%ss/%s", target, args[0]), obj)
		},
	}
}

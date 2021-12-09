package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/VirusTotal/vt-go"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var collectionCmdHelp = `Get information about one or more collections.

This command receives one or more collection IDs and returns information about
them. The information for each collection is returned in the same order as the
collections are passed to the command.

If the command receives a single hypen (-) the collection will be read from
the standard input, one per line.`

var collectionCmdExample = `  vt collection malpedia_win_emotet
  vt collection malpedia_win_emotet alienvault_603eb1abdd4812819c64e197
  cat list_of_collections | vt collection -`

// NewCollectionCmd returns a new instance of the 'collection' command.
func NewCollectionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "collection [collection]...",
		Short:   "Get information about collections",
		Long:    collectionCmdHelp,
		Example: collectionCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"collections/%s",
				utils.StringReaderFromCmdArgs(args),
				nil)
		},
	}

	cmd.AddCommand(createCollectionCmd())
	addRelationshipCmds(cmd, "collections", "collection", "[collection]")
	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

var createCollectionCmdHelp = `Creates a collection from a list of IOCs.

This command receives one of more IoCs (sha256 hashes, URLs, domains, IP addresses)
and creates a collection from them.

If the command receives a single hypen (-) the IoCs will be read from the
standard input.`

var createCollectionExample = `  vt collection create -n [collection_name] www.example.com
  vt collection create -n [collection_name] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection create -n [collection_name] -`

func createCollectionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create [ioc]...",
		Short:   "Create a collection.",
		Long:    createCollectionCmdHelp,
		Example: createCollectionExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			reader := utils.StringReaderFromCmdArgs(args)

			collection := vt.NewObject("collection")
			collection.SetString("name", viper.GetString("name"))
			collection.SetData("raw_items", rawFromReader(reader))

			if err := c.PostObject(vt.URL("collections"), collection); err != nil {
				return err
			}

			if viper.GetBool("identifiers-only") {
				fmt.Printf("%s\n", collection.ID())
			} else {
				if err := p.PrintObject(collection); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringP(
		"name", "n", "",
		"Collection's name (required)")
	_ = cmd.MarkFlagRequired("name")
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

func rawFromReader(reader utils.StringReader) string {
	var lines []string
	for {
		next, err := reader.ReadString()
		if err == io.EOF {
			break
		}
		lines = append(lines, next)
	}
	return strings.Join(lines, " ")
}

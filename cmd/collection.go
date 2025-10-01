package cmd

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/VirusTotal/vt-go"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type objectDescriptor struct {
	Type string `json:"type"`
	Id   string `json:"id,omitempty"`
	Url  string `json:"url,omitempty"`
}

var collectionCmdHelp = `Get information about one or more collections.

This command receives one or more collection IDs and returns information about
them. The information for each collection is returned in the same order as the
collections are passed to the command.

If the command receives a single hypen (-) the collection will be read from
the standard input, one per line.`

var collectionCmdExample = `  vt collection malpedia_win_emotet
  vt collection malpedia_win_emotet alienvault_603eb1abdd4812819c64e197
  cat list_of_collections | vt collection -n [collection_name] -d [collection_description] -`

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

	cmd.AddCommand(NewCollectionCreateCmd())
	cmd.AddCommand(NewCollectionRenameCmd())
	cmd.AddCommand(NewCollectionUpdateCmd())
	cmd.AddCommand(NewCollectionDeleteCmd())
	cmd.AddCommand(NewCollectionRemoveItemsCmd())

	addRelationshipCmds(cmd, "collections", "collection", "[collection]", false)
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

var createCollectionExample = `  vt collection create -n [collection_name] -d [collection_description] www.example.com
  vt collection create -n [collection_name] -d [collection_description] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection create -n [collection_name] -d [collection_description] -`

// NewCollectionCreateCmd returns a command for creating a collection.
func NewCollectionCreateCmd() *cobra.Command {
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
			collection.SetString("description", viper.GetString("description"))
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
	cmd.Flags().StringP(
		"description", "d", "",
		"Collection's description (required)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("description")
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

func patchCollection(id, attr string, value interface{}) error {
	client, err := NewAPIClient()
	if err != nil {
		return err
	}
	obj := vt.NewObjectWithID("collection", id)
	obj.Set(attr, value)
	return client.PatchObject(vt.URL("collections/%s", id), obj)
}

// NewCollectionRenameCmd returns a command for renaming a collection.
func NewCollectionRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename [collection id] [name]",
		Short: "Rename collection.",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchCollection(args[0], "name", args[1])
		},
	}
}

var updateCollectionCmdHelp = `Adds new items to a collection.

This command receives a collection ID and one of more IoCs
(sha256 hashes, URLs, domains, IP addresses) and adds them to the collection.

If the command receives a single hypen (-) the IoCs will be read from the
standard input.`

var updateCollectionExample = `  vt collection update [collection id] www.example.com
  vt collection update [collection id] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection update [collection id] -`

// NewCollectionUpdateCmd returns a command for adding new items to a collection.
func NewCollectionUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "update [collection id] [ioc]...",
		Short:   "Add new items to a collection.",
		Args:    cobra.MinimumNArgs(2),
		Long:    updateCollectionCmdHelp,
		Example: updateCollectionExample,

		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}

			collection := vt.NewObjectWithID("collection", args[0])
			reader := utils.StringReaderFromCmdArgs(args[1:])
			collection.SetData("raw_items", rawFromReader(reader))

			if err := c.PatchObject(vt.URL("collections/%s", args[0]), collection); err != nil {
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
}

var removeCollectionItemsCmdHelp = `Remove items from a collection.

This command receives a collection ID and one of more IoCs
(sha256 hashes, URLs, domains, IP addresses) and removes them from the collection.

If the command receives a single hypen (-) the IoCs will be read from the
standard input.`

var removeCollectionItemsExample = `  vt collection remove [collection id] www.example.com
  vt collection remove [collection id] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection remove [collection id] -`

// NewCollectionRemoveItemsCmd returns a command for removing items from a collection.
func NewCollectionRemoveItemsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove [collection id] [ioc]...",
		Short:   "Remove items from a collection.",
		Args:    cobra.MinimumNArgs(2),
		Long:    removeCollectionItemsCmdHelp,
		Example: removeCollectionItemsExample,

		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewAPIClient()
			if err != nil {
				return err
			}
			relationshipDescriptors := descriptorsFromReader(
				utils.StringReaderFromCmdArgs(args[1:]))
			for relationshipName, descriptors := range relationshipDescriptors {
				url := vt.URL("collections/%s/%s", args[0], relationshipName)
				response, err := c.DeleteData(url, descriptors)
				if err != nil {
					return err
				}
				if response.Error.Code != "" {
					return response.Error
				}
			}
			return nil
		},
	}
}

var deleteCollectionCmdHelp = `Delete a collection.

This command receives a collection ID and deletes it.`

var deleteCollectionExample = `  vt collection delete [collection id]`

// NewCollectionDeleteCmd returns a command for deleting a collection.
func NewCollectionDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete [collection id]",
		Short:   "Delete a collection.",
		Args:    cobra.MinimumNArgs(1),
		Long:    deleteCollectionCmdHelp,
		Example: deleteCollectionExample,

		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewAPIClient()
			if err != nil {
				return err
			}
			url := vt.URL("collections/%s", args[0])
			response, err := c.Delete(url)
			if err != nil {
				return err
			}
			if response.Error.Code != "" {
				return response.Error
			}
			return nil
		},
	}
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

func descriptorsFromReader(reader utils.StringReader) map[string][]objectDescriptor {
	descriptors := make(map[string][]objectDescriptor)
	hashPattern := regexp.MustCompile("[0-9a-fA-F]{32,64}")
	urlPattern := regexp.MustCompile("[hH][tTxX]{2}[pP][sS]?://.*")
	// At least two domain parts.
	domainPattern := regexp.MustCompile(".*[^.]+\\.[^.]+.*")
	for {
		next, err := reader.ReadString()
		if err == io.EOF {
			break
		}
		if match := hashPattern.MatchString(next); match {
			files := descriptors["files"]
			files = append(files, objectDescriptor{
				Type: "file",
				Id:   next,
			})
			descriptors["files"] = files
		} else if net.ParseIP(next) != nil {
			if strings.Contains(next, ".") {
				ipAddresses := descriptors["ip_addresses"]
				ipAddresses = append(ipAddresses, objectDescriptor{
					Type: "ip_address",
					Id:   next,
				})
				descriptors["ip_addresses"] = ipAddresses
			} else {
				// IPv6, skip.
			}
		} else if urlPattern.MatchString(next) {
			urls := descriptors["urls"]
			urls = append(urls, objectDescriptor{
				Type: "url",
				Url:  next,
			})
			descriptors["urls"] = urls
		} else if domainPattern.MatchString(next) {
			domains := descriptors["domains"]
			domains = append(domains, objectDescriptor{
				Type: "domain",
				Id:   next,
			})
			descriptors["domains"] = domains
		}
	}
	return descriptors
}

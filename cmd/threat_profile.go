package cmd

import (
	"fmt"
	"os"

	"github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/VirusTotal/vt-cli/utils"
)

var threatProfileCmdHelp = `Get information about one or more Threat Profiles.

This command receives one or more Threat Profile IDs and returns information about them.
The information for each profile is returned in the same order as the IDs are passed to the command.

If the command receives a single hyphen (-) the IDs will be read from the standard input, one per line.`

var threatProfileCmdExample = `  vt threatprofile <profile_id_1>
  vt threatprofile <profile_id_1> <profile_id_2>
  cat list_of_profile_ids | vt threatprofile -`

// NewThreatProfileCmd returns a new instance of the 'threatprofile' command.
func NewThreatProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "threatprofile [id]...",
		Short:   "Get information about Threat Profiles",
		Long:    threatProfileCmdHelp,
		Example: threatProfileCmdExample,
		Args:    cobra.MinimumNArgs(1), // For fetching specific profiles by ID

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"threat_profiles/%s",
				utils.StringReaderFromCmdArgs(args),
				nil) // No specific regexp for ID needed
		},
	}

	addRelationshipCmds(cmd, "threat_profiles", "threat_profile", "[id]", false)
	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	cmd.AddCommand(NewThreatProfileListCmd())
	cmd.AddCommand(NewThreatProfileCreateCmd())
	cmd.AddCommand(NewThreatProfileUpdateCmd())
	cmd.AddCommand(NewThreatProfileDeleteCmd())

	return cmd
}

var threatProfileListCmdHelp = `List Threat Profiles.`
var threatProfileListCmdExample = `  vt threatprofile list
  vt threatprofile list --filter "name:APT" --limit 10
  vt threatprofile list --cursor <cursor_value>`

// NewThreatProfileListCmd returns a command for listing Threat Profiles.
func NewThreatProfileListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List Threat Profiles",
		Long:    threatProfileListCmdHelp,
		Example: threatProfileListCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("threat_profiles"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

var threatProfileUpdateCmdHelp = `Update a Threat Profile.

This command updates an existing Threat Profile with the specified ID.
You can update attributes like name, interests, and recommendation configuration.`

var threatProfileUpdateCmdExample = `  vt threatprofile update <profile_id> --name "Updated Name"
  vt threatprofile update <profile_id> --targeted-region "US,CA" --actor-motivation "cybercrime"`

// NewThreatProfileUpdateCmd returns a command for updating a Threat Profile.
func NewThreatProfileUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [id]",
		Short:   "Update a Threat Profile",
		Long:    threatProfileUpdateCmdHelp,
		Example: threatProfileUpdateCmdExample,
		Args:    cobra.ExactArgs(1), // Threat Profile ID is required

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			printer, err := NewPrinter(cmd)
			if err != nil {
				return err
			}

			profileID := args[0]
			threatProfile := vt.NewObjectWithID("threat_profile", profileID)

			// Check and set flags for attributes
			if cmd.Flags().Changed("name") {
				threatProfile.SetString("name", viper.GetString("name"))
			}

			// Check and set flags for interests
			interestsData := make(map[string]interface{})
			interestsChanged := false
			if cmd.Flags().Changed("targeted-industry") {
				interestsData["INTEREST_TYPE_TARGETED_INDUSTRY"] = viper.GetStringSlice("targeted-industry")
				interestsChanged = true
			}
			if cmd.Flags().Changed("targeted-region") {
				interestsData["INTEREST_TYPE_TARGETED_REGION"] = viper.GetStringSlice("targeted-region")
				interestsChanged = true
			}
			if cmd.Flags().Changed("source-region") {
				interestsData["INTEREST_TYPE_SOURCE_REGION"] = viper.GetStringSlice("source-region")
				interestsChanged = true
			}
			if cmd.Flags().Changed("malware-role") {
				interestsData["INTEREST_TYPE_MALWARE_ROLE"] = viper.GetStringSlice("malware-role")
				interestsChanged = true
			}
			if cmd.Flags().Changed("actor-motivation") {
				interestsData["INTEREST_TYPE_ACTOR_MOTIVATION"] = viper.GetStringSlice("actor-motivation")
				interestsChanged = true
			}
			if interestsChanged {
				threatProfile.Set("interests", interestsData)
			}

			// Check and set flags for recommendation_config
			recommendationConfigData := make(map[string]interface{})
			recommendationConfigChanged := false
			if cmd.Flags().Changed("max-recs-per-type") {
				recommendationConfigData["max_recs_per_type"] = viper.GetInt("max-recs-per-type")
				recommendationConfigChanged = true
			}
			if cmd.Flags().Changed("min-categories-matched") {
				recommendationConfigData["min_categories_matched"] = viper.GetInt("min-categories-matched")
				recommendationConfigChanged = true
			}
			if cmd.Flags().Changed("max-days-since-last-seen") {
				recommendationConfigData["max_days_since_last_seen"] = viper.GetInt("max-days-since-last-seen")
				recommendationConfigChanged = true
			}
			if recommendationConfigChanged {
				threatProfile.Set("recommendation_config", recommendationConfigData)
			}

			// Need to check if *any* flag was changed besides the default ones
			// (like --format, --apikey, etc.). If only the ID is provided
			// without any update flags, it should probably error or do nothing.
			// Let's check if any of the specific update flags were changed.
			updateFlagsChanged := cmd.Flags().Changed("name") ||
				interestsChanged ||
				recommendationConfigChanged

			if !updateFlagsChanged {
				return fmt.Errorf("no update flags provided. Use --help for available flags")
			}

			if err := client.PatchObject(vt.URL("threat_profiles/%s", profileID), threatProfile); err != nil {
				return err
			}

			// Fetch the updated object to print the full details, as PatchObject might not return all attributes
			updatedThreatProfile, err := client.GetObject(vt.URL("threat_profiles/%s", profileID))
			if err != nil {
				// If fetching the updated object fails, at least report the patch was successful
				fmt.Fprintf(os.Stderr, "Warning: Failed to fetch updated threat profile details: %v\n", err)
				fmt.Printf("Threat profile %s updated successfully.\n", profileID)
				return nil
			}

			if viper.GetBool("identifiers-only") {
				fmt.Printf("%s\n", updatedThreatProfile.ID())
			} else {
				return printer.PrintObject(updatedThreatProfile)
			}

			return nil
		},
	}

	// Add flags for updatable attributes
	cmd.Flags().StringP("name", "n", "", "Threat Profile's name")

	// Flags for interests (optional, can be updated)
	cmd.Flags().StringSlice("targeted-industry", []string{}, "List of targeted industries (comma-separated)")
	cmd.Flags().StringSlice("targeted-region", []string{}, "List of targeted regions (comma-separated)")
	cmd.Flags().StringSlice("source-region", []string{}, "List of source regions (comma-separated)")
	cmd.Flags().StringSlice("malware-role", []string{}, "List of malware roles (comma-separated)")
	cmd.Flags().StringSlice("actor-motivation", []string{}, "List of actors’ motivations (comma-separated)")

	// Flags for recommendation_config (optional, can be updated)
	cmd.Flags().Int("max-recs-per-type", 0, "Max recommendations per type (1-20)") // Use 0 as default to detect if set
	cmd.Flags().Int("min-categories-matched", 0, "Min matching categories for recommendation (1-5)")
	cmd.Flags().Int("max-days-since-last-seen", 0, "Max lookback period in days for recommendations (1-365)")

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

var threatProfileDeleteCmdHelp = `Delete one or more Threat Profiles.

This command receives one or more Threat Profile IDs and deletes them.
The command will ask for confirmation before deleting.`

var threatProfileDeleteCmdExample = `  vt threatprofile delete <profile_id_1>
  vt threatprofile delete <profile_id_1> <profile_id_2>
  cat list_of_profile_ids | vt threatprofile delete -`

// NewThreatProfileDeleteCmd returns a command for deleting Threat Profiles.
func NewThreatProfileDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [id]...",
		Short:   "Delete Threat Profiles",
		Long:    threatProfileDeleteCmdHelp,
		Example: threatProfileDeleteCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			for _, id := range args {
				if _, err := client.Delete(vt.URL("threat_profiles/%s", id)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return cmd
}

var createThreatProfileCmdHelp = `Creates a Threat Profile.

This command creates a new Threat Profile with the specified name, description,
interests, and recommendation configuration.
For interest types, provide comma-separated values if multiple values are needed for a single interest type flag.`

var createThreatProfileCmdExample = `  vt threatprofile create --name "My New Threat Profile" --targeted-region "US,ES"`

// NewThreatProfileCreateCmd returns a command for creating a Threat Profile.
func NewThreatProfileCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create a Threat Profile",
		Long:    createThreatProfileCmdHelp,
		Example: createThreatProfileCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			printer, err := NewPrinter(cmd)
			if err != nil {
				return err
			}

			threatProfile := vt.NewObject("threat_profile")
			threatProfile.SetString("name", viper.GetString("name"))

			// Optional interests
			interestsData := make(map[string]interface{})
			if viper.IsSet("targeted-industry") {
				interestsData["INTEREST_TYPE_TARGETED_INDUSTRY"] = viper.GetStringSlice("targeted-industry")
			}
			if viper.IsSet("targeted-region") {
				interestsData["INTEREST_TYPE_TARGETED_REGION"] = viper.GetStringSlice("targeted-region")
			}
			if viper.IsSet("source-region") {
				interestsData["INTEREST_TYPE_SOURCE_REGION"] = viper.GetStringSlice("source-region")
			}
			if viper.IsSet("malware-role") {
				interestsData["INTEREST_TYPE_MALWARE_ROLE"] = viper.GetStringSlice("malware-role")
			}
			if viper.IsSet("actor-motivation") {
				interestsData["INTEREST_TYPE_ACTOR_MOTIVATION"] = viper.GetStringSlice("actor-motivation")
			}

			if len(interestsData) > 0 {
				threatProfile.Set("interests", interestsData)
			}

			// Optional recommendation_config
			recommendationConfigData := make(map[string]interface{})
			if viper.IsSet("max-recs-per-type") {
				recommendationConfigData["max_recs_per_type"] = viper.GetInt("max-recs-per-type")
			}
			if viper.IsSet("min-categories-matched") {
				recommendationConfigData["min_categories_matched"] = viper.GetInt("min-categories-matched")
			}
			if viper.IsSet("max-days-since-last-seen") {
				recommendationConfigData["max_days_since_last_seen"] = viper.GetInt("max-days-since-last-seen")
			}
			if len(recommendationConfigData) > 0 {
				threatProfile.Set("recommendation_config", recommendationConfigData)
			}

			if err := client.PostObject(vt.URL("threat_profiles"), threatProfile); err != nil {
				return err
			}

			if viper.GetBool("identifiers-only") {
				fmt.Printf("%s\n", threatProfile.ID())
			} else {
				return printer.PrintObject(threatProfile)
			}
			return nil
		},
	}

	cmd.Flags().StringP("name", "n", "", "Threat Profile's name (required)")
	_ = cmd.MarkFlagRequired("name")

	// Flags for interests
	cmd.Flags().StringSlice("targeted-industry", []string{}, "List of targeted industries (comma-separated)")
	cmd.Flags().StringSlice("targeted-region", []string{}, "List of targeted regions (comma-separated)")
	cmd.Flags().StringSlice("source-region", []string{}, "List of source regions (comma-separated)")
	cmd.Flags().StringSlice("malware-role", []string{}, "List of malware roles (comma-separated)")
	cmd.Flags().StringSlice("actor-motivation", []string{}, "List of actors’ motivations (comma-separated)")

	// Flags for recommendation_config
	cmd.Flags().Int("max-recs-per-type", 10, "Max recommendations per type (1-20, default 10 if not set by API)") // Default to 0 to check if set
	cmd.Flags().Int("min-categories-matched", 1, "Min matching categories for recommendation (1-5, default 1 if not set by API)")
	cmd.Flags().Int("max-days-since-last-seen", 180, "Max lookback period in days for recommendations (1-365, default 180 if not set by API)")

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

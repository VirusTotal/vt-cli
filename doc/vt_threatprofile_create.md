## vt threatprofile create

Create a Threat Profile

### Synopsis

Creates a Threat Profile.

This command creates a new Threat Profile with the specified name, description,
interests, and recommendation configuration.
For interest types, provide comma-separated values if multiple values are needed for a single interest type flag.

```
vt threatprofile create [flags]
```

### Examples

```
  vt threatprofile create --name "My New Threat Profile" --targeted-region "US,ES"
```

### Options

```
      --actor-motivation strings       List of actors’ motivations (comma-separated)
  -x, --exclude strings                exclude fields matching the provided pattern
  -h, --help                           help for create
  -I, --identifiers-only               print identifiers only
  -i, --include strings                include fields matching the provided pattern (default [**])
      --malware-role strings           List of malware roles (comma-separated)
      --max-days-since-last-seen int   Max lookback period in days for recommendations (1-365, default 180 if not set by API) (default 180)
      --max-recs-per-type int          Max recommendations per type (1-20, default 10 if not set by API) (default 10)
      --min-categories-matched int     Min matching categories for recommendation (1-5, default 1 if not set by API) (default 1)
  -n, --name string                    Threat Profile's name (required)
      --source-region strings          List of source regions (comma-separated)
      --targeted-industry strings      List of targeted industries (comma-separated)
      --targeted-region strings        List of targeted regions (comma-separated)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt threatprofile](vt_threatprofile.md)	 - Get information about Threat Profiles


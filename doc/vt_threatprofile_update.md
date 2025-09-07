## vt threatprofile update

Update a Threat Profile

### Synopsis

Update a Threat Profile.

This command updates an existing Threat Profile with the specified ID.
You can update attributes like name, interests, and recommendation configuration.

```
vt threatprofile update [id] [flags]
```

### Examples

```
  vt threatprofile update <profile_id> --name "Updated Name"
  vt threatprofile update <profile_id> --targeted-region "US,CA" --actor-motivation "cybercrime"
```

### Options

```
      --actor-motivation strings       List of actors’ motivations (comma-separated)
  -x, --exclude strings                exclude fields matching the provided pattern
  -h, --help                           help for update
  -I, --identifiers-only               print identifiers only
  -i, --include strings                include fields matching the provided pattern (default [**])
      --malware-role strings           List of malware roles (comma-separated)
      --max-days-since-last-seen int   Max lookback period in days for recommendations (1-365)
      --max-recs-per-type int          Max recommendations per type (1-20)
      --min-categories-matched int     Min matching categories for recommendation (1-5)
  -n, --name string                    Threat Profile's name
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


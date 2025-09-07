## vt threatprofile list

List Threat Profiles

### Synopsis

List Threat Profiles.

```
vt threatprofile list [flags]
```

### Examples

```
  vt threatprofile list
  vt threatprofile list --filter "name:APT" --limit 10
  vt threatprofile list --cursor <cursor_value>
```

### Options

```
  -c, --cursor string      cursor for continuing where the previous request left
  -x, --exclude strings    exclude fields matching the provided pattern
  -f, --filter string      filter
  -h, --help               help for list
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -n, --limit int          maximum number of results (default 10)
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


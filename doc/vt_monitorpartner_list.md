## vt monitorpartner list

List available monitor partner hashes

```
vt monitorpartner list [flags]
```

### Examples

```
  vt monitorpartner list
  vt monitorpartner list --filter "engine:<EngineName>" --include sha256,first_detection_date
```

### Options

```
  -c, --cursor string     cursor for continuing where the previous request left
  -x, --exclude strings   exclude fields matching the provided pattern
  -f, --filter string     filter
  -h, --help              help for list
  -i, --include strings   include fields matching the provided pattern (default [**])
  -n, --limit int         maximum number of results (default 10)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt monitorpartner](vt_monitorpartner.md)	 - Manage your monitor partner account


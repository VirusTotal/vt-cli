## vt monitor list

List monitor in your account

```
vt monitor list [flags]
```

### Examples

```
  vt monitor list
  vt monitor list --filter "path:/myfolder/" --include path
  vt monitor list --filter "tag:detected" --include path,last_analysis_results.*.result,last_detections_count
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

* [vt monitor](vt_monitor.md)	 - Manage your monitor account


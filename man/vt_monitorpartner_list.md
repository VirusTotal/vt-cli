## vt monitorpartner list

List available monitor partner hashes

```
vt monitorpartner list [flags]
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
      --proxy string    HTTP proxy
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt monitorpartner](vt_monitorpartner.md)	 - Manage your monitor partner account


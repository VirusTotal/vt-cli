## vt iocstream list

List IoCs from notifications

```
vt iocstream list [flags]
```

### Examples

```
# List notifications from a hunting rule by name
vt iocstream list -f "origin:hunting tag:my_rule"
# List notifications from a hunting ruleset by name
vt iocstream list -f "origin:hunting tag:myRuleset"
# List just the entity IDs of your IoC Stream matches
vt iocstream list -I
# List ALL the entity IDs in your IoC Stream and store them in a csv file (this might take a while)
vt iocstream list -I –limit 9999999 > results.csv
# List the first IoC Stream notifications including the hash, last_analysis_stats, size and file type
vt iocstream list -i "_id,last_analysis_stats,size,type_tag"
# Check if a hash is in your IoC Stream matches
vt iocstream list -f "entity_type:file entity_id:hash"
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

* [vt iocstream](vt_iocstream.md)	 - Manage IoC Stream notifications


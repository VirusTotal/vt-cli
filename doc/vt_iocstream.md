## vt iocstream

Manage IoC Stream notifications

```
vt iocstream [notification_id]... [flags]
```

### Examples

```
## List:
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

## Delete:
# Delete all notifications matching a filter, e.g. all matches for a YARA rule/ruleset. This process is
# asynchronous, so it can take a while to delete all the notifications.
vt iocstream delete -f "origin:hunting tag:my_rule"
# Delete a single notification with ID 1234568. The notification ID is displayed in the context_attributes.
vt iocstream delete 1234568
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for iocstream
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -t, --threads int        number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt](vt.md)	 - A command-line tool for interacting with VirusTotal
* [vt iocstream delete](vt_iocstream_delete.md)	 - Deletes notifications from the IoC Stream
* [vt iocstream list](vt_iocstream_list.md)	 - List IoCs from notifications


## vt iocstream delete

Deletes notifications from the IoC Stream

### Synopsis

Delete notifications from the IoC Stream.

The command accepts a list of IoC Stream notification IDs. If no IDs are provided,
then all the IoC Stream notifications matching the given filter are deleted.


```
vt iocstream delete [notification id]... [flags]
```

### Examples

```
# Delete all notifications matching a filter, e.g. all matches for a YARA rule/ruleset
vt iocstream delete -f "origin:hunting tag:my_rule"
# Delete a single notification with ID 1234568. The notification ID is displayed in the context_attributes.
vt iocstream delete 1234568
```

### Options

```
  -f, --filter string   filter
  -h, --help            help for delete
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


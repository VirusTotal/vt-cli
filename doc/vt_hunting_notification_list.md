## vt hunting notification list

List notifications

### Synopsis

List malware hunting notifications.

This command list the malware hunting notifications associated to the currently
configured API key.

```
vt hunting notification list [flags]
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

* [vt hunting notification](vt_hunting_notification.md)	 - Manage malware hunting notifications
* [vt hunting notification list delete](vt_hunting_notification_list_delete.md)	 - Delete hunting notifications


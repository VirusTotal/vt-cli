## vt hunting notification

Manage malware hunting notifications

```
vt hunting notification [id]... [flags]
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for notification
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

* [vt hunting](vt_hunting.md)	 - Manage malware hunting rules and notifications
* [vt hunting notification delete](vt_hunting_notification_delete.md)	 - Delete hunting notifications
* [vt hunting notification list](vt_hunting_notification_list.md)	 - List notifications


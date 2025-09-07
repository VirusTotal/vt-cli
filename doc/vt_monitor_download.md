## vt monitor download

Download files from your monitor account

### Synopsis

Download files from your account.

This command download files in your monitor account using their MonitorItemID.

```
vt monitor download [monitor_id]... [flags]
```

### Examples

```
  vt monitor download "MonitorItemID"
  vt monitor download "MonitorItemID1" "MonitorItemID2" ...
  cat list_of_monitor_ids | vt monitor download -
```

### Options

```
  -h, --help            help for download
  -o, --output string   directory where downloaded files are put (default ".")
  -t, --threads int     number of threads working in parallel (default 5)
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


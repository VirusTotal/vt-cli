## vt monitor delete

Delete monitor files

### Synopsis

Delete files in your account.

This command deletes files in your monitor account using a MonitorItemID,
deleting a folder recursivelly deletes all files and folders inside it.

```
vt monitor delete [monitor_id]... [flags]
```

### Options

```
  -h, --help   help for delete
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


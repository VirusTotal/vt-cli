## vt monitorpartner download

Download files from your monitor partner account

### Synopsis

Download files from your partner account.

This command download files from your monitor partner account using their sha256.

```
vt monitorpartner download [sha256]... [flags]
```

### Examples

```
  vt monitorpartner download <sha256-1> <sha256-2> ...
  cat list_of_monitor_ids | vt monitorpartner download -
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

* [vt monitorpartner](vt_monitorpartner.md)	 - Manage your monitor partner account


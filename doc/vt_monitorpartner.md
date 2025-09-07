## vt monitorpartner

Manage your monitor partner account

### Synopsis

Manage your VirusTotal Monitor Partner account.

This command allows you to list and retrieve files detected by your engine.

Reference:
  https://docs.virustotal.com/reference/monitor-partner

### Options

```
  -x, --exclude strings   exclude fields matching the provided pattern
  -h, --help              help for monitorpartner
  -i, --include strings   include fields matching the provided pattern (default [**])
  -t, --threads int       number of threads working in parallel (default 5)
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
* [vt monitorpartner download](vt_monitorpartner_download.md)	 - Download files from your monitor partner account
* [vt monitorpartner list](vt_monitorpartner_list.md)	 - List available monitor partner hashes
* [vt monitorpartner relationships](vt_monitorpartner_relationships.md)	 - Get all relationships.


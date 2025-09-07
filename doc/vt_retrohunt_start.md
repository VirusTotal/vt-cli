## vt retrohunt start

Start a retrohunt job

### Synopsis

Start a retrohunt job.

This command receives a file containing YARA rules and starts a retrohunt job with those rules.

```
vt retrohunt start [file] [flags]
```

### Options

```
      --after string    scan files sent to VirusTotal after the given date (format: YYYY-MM-DD)
      --before string   scan files sent to VirusTotal before the given date (format: YYYY-MM-DD)
      --corpus string   specify the corpus that will be scanned, possible values are "main" and "goodware" (default "main")
  -h, --help            help for start
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt retrohunt](vt_retrohunt.md)	 - Manage retrohunt jobs


## vt scan url

Scan one of more URLs

### Synopsis

Scan one or more URLs.

This command receives one or more URLs and scan them. It returns the URLs followed
by their corresponding analysis IDs. You can use the "vt analysis" command for
retrieving information about the analyses or you can use the --wait
flag to see the results when the analysis is completed.

If the command receives a single hypen (-) the URLs are read from the standard
input, one per line.

```
vt scan url [url]... [flags]
```

### Examples

```
  vt scan url http://foo.com
  vt scan url http://foo.com http://bar.com
  cat list_of_urls | vt scan urls -
```

### Options

```
  -h, --help          help for url
  -o, --open          Return an URL to see the analysis report at the VirusTotal web GUI
  -t, --threads int   number of threads working in parallel (default 5)
  -w, --wait          Wait until the analysis is completed and show the analysis results
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt scan](vt_scan.md)	 - Scan files or URLs


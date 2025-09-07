## vt search

Search for files in VirusTotal Intelligence

### Synopsis

Search for files using VirusTotal Intelligence's query language.

```
vt search [query] [flags]
```

### Examples

```
  vt search eicar
  vt search "foobar p:1+"
```

### Options

```
  -c, --cursor string      cursor for continuing where the previous request left
  -d, --download           download files that match the query
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for search
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -n, --limit int          maximum number of results (default 10)
  -o, --output string      directory where downloaded files are put (default ".")
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
* [vt search content](vt_search_content.md)	 - Search for patterns within files in VirusTotal Intelligence


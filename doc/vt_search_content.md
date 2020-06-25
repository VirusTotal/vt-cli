## vt search content

Search for patterns within files in VirusTotal Intelligence

### Synopsis

Search for content within files in VirusTotal

```
vt search content [query] [flags]
```

### Examples

```
  vt search content foobarbaz
  vt search content '"foo bar baz"'
  vt search content {cafebabe}
  vt search content '{70 6C 75 73 76 69 63 [1] 79 61 72 61}'
  vt search content '/virustotal(.org|.com)/'
```

### Options

```
  -c, --cursor string        cursor
  -d, --download             download files
  -e, --exact-matches-only   exact matches only
  -h, --help                 help for content
  -I, --identifiers-only     print identifiers only
  -n, --limit int            maximum number of results (default 10)
  -t, --threads int          number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   api key
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt search](vt_search.md)	 - Search for files in VirusTotal Intelligence


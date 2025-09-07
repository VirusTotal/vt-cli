## vt collection remove

Remove items from a collection.

### Synopsis

Remove items from a collection.

This command receives a collection ID and one of more IoCs
(sha256 hashes, URLs, domains, IP addresses) and removes them from the collection.

If the command receives a single hypen (-) the IoCs will be read from the
standard input.

```
vt collection remove [collection id] [ioc]... [flags]
```

### Examples

```
  vt collection remove [collection id] www.example.com
  vt collection remove [collection id] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection remove [collection id] -
```

### Options

```
  -h, --help   help for remove
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt collection](vt_collection.md)	 - Get information about collections


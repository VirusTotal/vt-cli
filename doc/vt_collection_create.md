## vt collection create

Create a collection.

### Synopsis

Creates a collection from a list of IOCs.

This command receives one of more IoCs (sha256 hashes, URLs, domains, IP addresses)
and creates a collection from them.

If the command receives a single hypen (-) the IoCs will be read from the
standard input.

```
vt collection create [ioc]... [flags]
```

### Examples

```
  vt collection create -n [collection_name] -d [collection_description] www.example.com
  vt collection create -n [collection_name] -d [collection_description] www.example.com 8.8.8.8
  cat list_of_iocs | vt collection create -n [collection_name] -d [collection_description] -
```

### Options

```
  -d, --description string   Collection's description (required)
  -x, --exclude strings      exclude fields matching the provided pattern
  -h, --help                 help for create
  -I, --identifiers-only     print identifiers only
  -i, --include strings      include fields matching the provided pattern (default [**])
  -n, --name string          Collection's name (required)
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


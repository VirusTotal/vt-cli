## vt file execution_parents

Files that executed the file.

```
vt file execution_parents [hash] [flags]
```

### Options

```
  -c, --cursor string      cursor for continuing where the previous request left
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for execution_parents
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -n, --limit int          maximum number of results (default 10)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt file](vt_file.md)	 - Get information about files


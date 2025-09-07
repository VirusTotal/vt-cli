## vt file user_votes

Item's votes made by current signed-in user.

```
vt file user_votes [hash] [flags]
```

### Options

```
  -c, --cursor string      cursor for continuing where the previous request left
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for user_votes
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


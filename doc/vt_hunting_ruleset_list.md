## vt hunting ruleset list

List rulesets

### Synopsis

List malware hunting rulesets.

This command list the malware hunting rulesets associated to the currently
configured API key.

```
vt hunting ruleset list [flags]
```

### Options

```
  -c, --cursor string      cursor for continuing where the previous request left
  -x, --exclude strings    exclude fields matching the provided pattern
  -f, --filter string      filter
  -h, --help               help for list
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

* [vt hunting ruleset](vt_hunting_ruleset.md)	 - Manage hunting rulesets


## vt group privileges grant

Grant privileges to a group

```
vt group privileges grant [groupname] [privilege]... [flags]
```

### Examples

```
  vt group privileges grant mygroup intelligence downloads-tier-2
```

### Options

```
  -e, --expiration string   expiration time for the granted privileges (UNIX timestamp or YYYY-MM-DD)
  -h, --help                help for grant
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt group privileges](vt_group_privileges.md)	 - Change group privileges


## vt user privileges grant

Grant privileges to a user

```
vt user privileges grant [username] [privilege]... [flags]
```

### Examples

```
  vt user privileges grant myuser intelligence downloads-tier-2
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

* [vt user privileges](vt_user_privileges.md)	 - Change user privileges


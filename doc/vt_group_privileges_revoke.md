## vt group privileges revoke

Revoke privileges from a group

```
vt group privileges revoke [groupname] [privilege]... [flags]
```

### Examples

```
  vt group privileges revoke mygroup intelligence downloads-tier-2
```

### Options

```
  -h, --help   help for revoke
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


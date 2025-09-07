## vt user privileges revoke

Revoke privileges from a user

```
vt user privileges revoke [username] [privilege]... [flags]
```

### Examples

```
  vt user privileges revoke myuser intelligence downloads-tier-2
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

* [vt user privileges](vt_user_privileges.md)	 - Change user privileges


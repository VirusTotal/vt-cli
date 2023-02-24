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
      --proxy string    HTTP proxy
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt group privileges](vt_group_privileges.md)	 - Change group privileges


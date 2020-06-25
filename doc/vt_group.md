## vt group

Get information about VirusTotal groups

### Synopsis

Get information about a group.

```
vt group [groupname]... [flags]
```

### Examples

```
  vt group mygroup
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for group
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -t, --threads int        number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   api key
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt](vt.md)	 - A command-line tool for interacting with VirusTotal
* [vt group privileges](vt_group_privileges.md)	 - Change group privileges


## vt user

Get information about VirusTotal users

### Synopsis

Get information about a VirusTotal user.

```
vt user [username | apikey | email]... [flags]
```

### Examples

```
  vt user joe
  vt user 1ebb658141155c16d8bf89629379098b4cf31d4613b13784a108c6a4805c963b
  vt user joe@domain.com
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for user
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -t, --threads int        number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt](vt.md)	 - A command-line tool for interacting with VirusTotal
* [vt user privileges](vt_user_privileges.md)	 - Change user privileges


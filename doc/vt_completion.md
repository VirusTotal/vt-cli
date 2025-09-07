## vt completion

Output shell completion code for the specified shell (bash or zsh)

### Synopsis

Output shell completion code for the specified shell (bash or zsh).

The shell code must be evaluated to provide interactive completion of vt commands.  This can be done by sourcing it from
the .bash_profile.

Note for zsh users: [1] zsh completions are only supported in versions of zsh >= 5.2

```
vt completion <shell> [flags]
```

### Options

```
  -h, --help   help for completion
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


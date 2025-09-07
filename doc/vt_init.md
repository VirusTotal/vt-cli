## vt init

Initialize or re-initialize vt command-line tool

### Synopsis

Initialize or re-initialize this command-line tool.

This command will ask for your API key and save it in a local file, so you don't
need to enter it everytime you use the tool. It will also retrieve additional
metadata from VirusTotal for making the tool even more powerful.

```
vt init [flags]
```

### Options

```
  -h, --help   help for init
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


## vt download

Download files

### Synopsis

Download one or more files.

This command receives one or more file hashes (SHA-256, SHA-1 or MD5) and
downloads the files from VirusTotal. For using this command you need an API
key with access to VirusTotal Intelligence.

If the command receives a single hypen (-) the hashes are read from the standard
input, one per line.

```
vt download [flags]
```

### Examples

```
  vt download 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
  vt download 76cdb2bad9582d23c1f6f4d868218d6c 44d88612fea8a8f36de82e1278abb02f
  cat list_of_hashes | vt download -
```

### Options

```
  -h, --help                  help for download
  -o, --output string         directory where downloaded files are put (default ".")
  -t, --threads int           number of threads working in parallel (default 5)
  -z, --zip                   download in a ZIP file
      --zip-password string   password for the ZIP file, used with --zip
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


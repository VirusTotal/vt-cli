## vt scan file

Scan one or more files

### Synopsis

Scan one or more files.

This command receives one or more file paths and uploads them to VirusTotal for
scanning. It returns the file paths followed by their corresponding analysis IDs.
You can use the "vt analysis" command for retrieving information about the
analyses.

If the command receives a single hypen (-) the file paths are read from the standard
input, one per line.

The command can also receive a directory to scan all files contained on it.

```
vt scan file [[dir] | [file]...] [flags]
```

### Examples

```
  vt scan file foo.exe
  vt scan file foo.exe bar.exe
	vt scan file foo/
  cat list_of_file_paths | vt scan file -
```

### Options

```
  -h, --help          help for file
  -o, --open          Return an URL to see the analysis report at the VirusTotal web GUI
  -t, --threads int   number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --proxy string    HTTP proxy
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt scan](vt_scan.md)	 - Scan files or URLs


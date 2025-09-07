## vt monitor upload

Upload one or more files to your account

### Synopsis

Upload a file or files contained in a folder.

This command receives one file or folder path and uploads them to your
VirusTotal Monitor account. It returns uploaded the file paths followed by their
corresponding monitor ID.
You can use the "vt monitor [monitor_id]" command for retrieving
information about the it.

```
vt monitor upload [file/folder] [remote_path] [flags]
```

### Examples

```
  vt monitor item upload foo.exe /remote_folder/foo.exe
  vt monitor item upload myfolder/ /another_remote_folder/
```

### Options

```
  -h, --help          help for upload
  -t, --threads int   number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt monitor](vt_monitor.md)	 - Manage your monitor account


## vt monitor setdetails

Sets details metadata for a monitor file

### Synopsis

Set details metadata for a file.

This command sets details metadata for a file in your monitor account
referenced by a MonitorItemID.

```
vt monitor setdetails [monitor_id] [details_string] [flags]
```

### Examples

```
  vt monitor setdetails "MonitorItemID" "Some file metadata."
  cat multiline_details | vt monitor setdetails "MonitorItemID"
```

### Options

```
  -h, --help   help for setdetails
```

### Options inherited from parent commands

```
  -k, --apikey string   api key
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt monitor](vt_monitor.md)	 - Manage your monitor account


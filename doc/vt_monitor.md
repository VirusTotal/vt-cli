## vt monitor

Manage your monitor account

### Synopsis

Manage your VirusTotal Monitor account.

This command allows you to manage the contents of your account and retrieve
information about analyses performed to your collection.

Reference:
  https://developers.virustotal.com/v3.0/reference#monitor

```
vt monitor [monitor_id]... [flags]
```

### Options

```
  -x, --exclude strings   exclude fields matching the provided pattern
  -h, --help              help for monitor
  -i, --include strings   include fields matching the provided pattern (default [**])
  -t, --threads int       number of threads working in parallel (default 5)
```

### Options inherited from parent commands

```
  -k, --apikey string   api key
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt](vt.md)	 - A command-line tool for interacting with VirusTotal
* [vt monitor analyses](vt_monitor_analyses.md)	 - Analyses for the hash.
* [vt monitor comments](vt_monitor_comments.md)	 - Comments for the hash.
* [vt monitor delete](vt_monitor_delete.md)	 - Delete monitor files
* [vt monitor deletedetails](vt_monitor_deletedetails.md)	 - Download files from your monitor account
* [vt monitor download](vt_monitor_download.md)	 - Download files from your monitor account
* [vt monitor list](vt_monitor_list.md)	 - List monitor in your account
* [vt monitor owner](vt_monitor_owner.md)	 - User or group owning the item.
* [vt monitor relationships](vt_monitor_relationships.md)	 - Get all relationships.
* [vt monitor setdetails](vt_monitor_setdetails.md)	 - Sets details metadata for a monitor file
* [vt monitor upload](vt_monitor_upload.md)	 - Upload one or more files to your account


## vt hunting notification delete

Delete hunting notifications

### Synopsis

Delete hunting notifications.

This command deletes the malware hunting notifications associated to the
currently configured API key.

```
vt hunting notification delete [notification id]... [flags]
```

### Options

```
  -a, --all               delete all notifications
  -h, --help              help for delete
  -t, --with-tag string   delete notifications with a given tag
```

### Options inherited from parent commands

```
  -k, --apikey string   api key
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt hunting notification](vt_hunting_notification.md)	 - Manage malware hunting notifications


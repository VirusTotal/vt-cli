## vt hunting notification list delete

Delete hunting notifications

### Synopsis

Delete hunting notifications.

This command deletes the malware hunting notifications associated to the
currently configured API key.

```
vt hunting notification list delete [notification id]... [flags]
```

### Options

```
  -a, --all               delete all notifications
  -h, --help              help for delete
  -t, --with-tag string   delete notifications with a given tag
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --proxy string    HTTP proxy
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt hunting notification list](vt_hunting_notification_list.md)	 - List notifications


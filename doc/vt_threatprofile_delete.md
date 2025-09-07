## vt threatprofile delete

Delete Threat Profiles

### Synopsis

Delete one or more Threat Profiles.

This command receives one or more Threat Profile IDs and deletes them.
The command will ask for confirmation before deleting.

```
vt threatprofile delete [id]... [flags]
```

### Examples

```
  vt threatprofile delete <profile_id_1>
  vt threatprofile delete <profile_id_1> <profile_id_2>
  cat list_of_profile_ids | vt threatprofile delete -
```

### Options

```
  -h, --help   help for delete
```

### Options inherited from parent commands

```
  -k, --apikey string   API key
      --format string   Output format (yaml/json/csv) (default "yaml")
  -s, --silent          Silent or quiet mode. Do not show progress meter
  -v, --verbose         verbose output
```

### SEE ALSO

* [vt threatprofile](vt_threatprofile.md)	 - Get information about Threat Profiles


## vt threatprofile

Get information about Threat Profiles

### Synopsis

Get information about one or more Threat Profiles.

This command receives one or more Threat Profile IDs and returns information about them.
The information for each profile is returned in the same order as the IDs are passed to the command.

If the command receives a single hyphen (-) the IDs will be read from the standard input, one per line.

```
vt threatprofile [id]... [flags]
```

### Examples

```
  vt threatprofile <profile_id_1>
  vt threatprofile <profile_id_1> <profile_id_2>
  cat list_of_profile_ids | vt threatprofile -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for threatprofile
  -I, --identifiers-only   print identifiers only
  -i, --include strings    include fields matching the provided pattern (default [**])
  -t, --threads int        number of threads working in parallel (default 5)
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
* [vt threatprofile create](vt_threatprofile_create.md)	 - Create a Threat Profile
* [vt threatprofile delete](vt_threatprofile_delete.md)	 - Delete Threat Profiles
* [vt threatprofile list](vt_threatprofile_list.md)	 - List Threat Profiles
* [vt threatprofile relationships](vt_threatprofile_relationships.md)	 - Get all relationships.
* [vt threatprofile update](vt_threatprofile_update.md)	 - Update a Threat Profile


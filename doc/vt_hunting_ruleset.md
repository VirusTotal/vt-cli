## vt hunting ruleset

Manage hunting rulesets

```
vt hunting ruleset [id]... [flags]
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for ruleset
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

* [vt hunting](vt_hunting.md)	 - Manage malware hunting rules and notifications
* [vt hunting ruleset add](vt_hunting_ruleset_add.md)	 - Add a new ruleset
* [vt hunting ruleset delete](vt_hunting_ruleset_delete.md)	 - Delete rulesets
* [vt hunting ruleset disable](vt_hunting_ruleset_disable.md)	 - Disable ruleset
* [vt hunting ruleset enable](vt_hunting_ruleset_enable.md)	 - Enable ruleset
* [vt hunting ruleset list](vt_hunting_ruleset_list.md)	 - List rulesets
* [vt hunting ruleset notification_emails](vt_hunting_ruleset_notification_emails.md)	 - Set ruleset notification emails
* [vt hunting ruleset rename](vt_hunting_ruleset_rename.md)	 - Rename ruleset
* [vt hunting ruleset setlimit](vt_hunting_ruleset_setlimit.md)	 - Set ruleset limit
* [vt hunting ruleset update](vt_hunting_ruleset_update.md)	 - Change the rules for a ruleset


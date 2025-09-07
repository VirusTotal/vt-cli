## vt analysis

Get a file or URL analysis

### Synopsis

Get a file or URL analysis.

This command receives one or more analysis identifiers and returns information
about the analysis. The data is returned in the same order as the identifiers
appear in the command line.

If the command receives a single hypen (-) the analysis identifiers are read 
from the standard input, one per line.


```
vt analysis [hash]... [flags]
```

### Examples

```
  vt analysis f-e04b82f7f8afc6e599d4913bee5eb571921ec8958d1ea5e3bbffe9c7ea9a0960-1542306475
  vt analysis u-1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1542292491
  cat list_of_analysis_ids | vt analysis -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for analysis
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


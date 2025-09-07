## vt domain

Get information about Internet domains

### Synopsis

Get information about one or more Internet domains.

This command receives one or more Internet domains and returns information about
them. The data is returned in the same order as the domains appear in the
command line.

If the command receives a single hypen (-) the domains are read from the standard
input, one per line.


```
vt domain [domain]... [flags]
```

### Examples

```
  vt domain virustotal.com
  vt domain virustotal.com google.com
  cat list_of_domains | vt domain -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for domain
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
* [vt domain associations](vt_domain_associations.md)	 - Returns the collections related to the IOC.
* [vt domain caa_records](vt_domain_caa_records.md)	 - Records CAA for the domain.
* [vt domain campaigns](vt_domain_campaigns.md)	 - IOC's related campaigns.
* [vt domain cname_records](vt_domain_cname_records.md)	 - Records CNAME for the domain.
* [vt domain collections](vt_domain_collections.md)	 - Returns the collections related to the IOC.
* [vt domain comments](vt_domain_comments.md)	 - Comments for the domain or IP address.
* [vt domain communicating_files](vt_domain_communicating_files.md)	 - Files that communicate with the domain.
* [vt domain downloaded_files](vt_domain_downloaded_files.md)	 - Files downloaded from the domain.
* [vt domain graphs](vt_domain_graphs.md)	 - Graphs containing the domain/ip.
* [vt domain historical_ssl_certificates](vt_domain_historical_ssl_certificates.md)	 - SSL certificate history.
* [vt domain historical_whois](vt_domain_historical_whois.md)	 - Historical Whois.
* [vt domain immediate_parent](vt_domain_immediate_parent.md)	 - Immediate parent domain.
* [vt domain malware_families](vt_domain_malware_families.md)	 - IOC's related malware families.
* [vt domain memory_pattern_parents](vt_domain_memory_pattern_parents.md)	 - Files having a domain as string on memory during sandbox execution.
* [vt domain mx_records](vt_domain_mx_records.md)	 - Records MX for the domain.
* [vt domain ns_records](vt_domain_ns_records.md)	 - Records NS for the domain.
* [vt domain parent](vt_domain_parent.md)	 - Parent domain.
* [vt domain references](vt_domain_references.md)	 - Returns the References related to the domain.
* [vt domain referrer_files](vt_domain_referrer_files.md)	 - Files containing the domain.
* [vt domain related_comments](vt_domain_related_comments.md)	 - Comments for the Domain or IP's related entities.
* [vt domain related_references](vt_domain_related_references.md)	 - Returns the direct and related references containing this domain.
* [vt domain related_reports](vt_domain_related_reports.md)	 - IOC's related reports
* [vt domain related_threat_actors](vt_domain_related_threat_actors.md)	 - IOC's related threat actors.
* [vt domain relationships](vt_domain_relationships.md)	 - Get all relationships.
* [vt domain reports](vt_domain_reports.md)	 - IOC's related reports.
* [vt domain resolutions](vt_domain_resolutions.md)	 - DNS resolutions for the domain.
* [vt domain siblings](vt_domain_siblings.md)	 - Subdomains that share the same domain.
* [vt domain soa_records](vt_domain_soa_records.md)	 - Records SOA for the domain.
* [vt domain software_toolkits](vt_domain_software_toolkits.md)	 - IOC's related software toolkits.
* [vt domain subdomains](vt_domain_subdomains.md)	 - Subdomains of the domain.
* [vt domain urls](vt_domain_urls.md)	 - URLs related to the domain.
* [vt domain user_votes](vt_domain_user_votes.md)	 - Item's votes made by current signed-in user.
* [vt domain votes](vt_domain_votes.md)	 - Item's votes.
* [vt domain vulnerabilities](vt_domain_vulnerabilities.md)	 - IOC's related vulnerabilities.


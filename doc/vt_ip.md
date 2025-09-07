## vt ip

Get information about IP addresses

### Synopsis

Get information about one or more IP addresses.

This command receives one or more IP addresses and returns information about
them. The information for each IP address is returned in the same order as the
IP addresses are passed to the command.

If the command receives a single hypen (-) the IP addresses will be read from
the standard input, one per line.

```
vt ip [ip]... [flags]
```

### Examples

```
  vt ip 8.8.8.8
  vt ip 8.8.8.8 8.8.4.4
  cat list_of_ips | vt ip -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for ip
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
* [vt ip associations](vt_ip_associations.md)	 - Returns the collections related to the IOC.
* [vt ip campaigns](vt_ip_campaigns.md)	 - IOC's related campaigns.
* [vt ip collections](vt_ip_collections.md)	 - Returns the collections related to the IOC.
* [vt ip comments](vt_ip_comments.md)	 - Comments for the domain or IP address.
* [vt ip communicating_files](vt_ip_communicating_files.md)	 - Files that communicate with the ip.
* [vt ip downloaded_files](vt_ip_downloaded_files.md)	 - Files downloaded from the ip.
* [vt ip graphs](vt_ip_graphs.md)	 - Graphs containing the domain/ip.
* [vt ip historical_ssl_certificates](vt_ip_historical_ssl_certificates.md)	 - SSL certificate history.
* [vt ip historical_whois](vt_ip_historical_whois.md)	 - Historical Whois.
* [vt ip malware_families](vt_ip_malware_families.md)	 - IOC's related malware families.
* [vt ip memory_pattern_parents](vt_ip_memory_pattern_parents.md)	 - Files having a IP as string on memory during sandbox execution.
* [vt ip references](vt_ip_references.md)	 - Returns the References related to the IP Address.
* [vt ip referrer_files](vt_ip_referrer_files.md)	 - Files containing the domain/ip.
* [vt ip related_comments](vt_ip_related_comments.md)	 - Comments for the Domain or IP's related entities.
* [vt ip related_references](vt_ip_related_references.md)	 - Returns the direct and related references containing this IP.
* [vt ip related_reports](vt_ip_related_reports.md)	 - IOC's related reports
* [vt ip related_threat_actors](vt_ip_related_threat_actors.md)	 - IOC's related threat actors.
* [vt ip relationships](vt_ip_relationships.md)	 - Get all relationships.
* [vt ip reports](vt_ip_reports.md)	 - IOC's related reports.
* [vt ip resolutions](vt_ip_resolutions.md)	 - DNS resolutions for the IP address.
* [vt ip software_toolkits](vt_ip_software_toolkits.md)	 - IOC's related software toolkits.
* [vt ip urls](vt_ip_urls.md)	 - URLs related to the ip.
* [vt ip user_votes](vt_ip_user_votes.md)	 - Item's votes made by current signed-in user.
* [vt ip votes](vt_ip_votes.md)	 - Item's votes.
* [vt ip vulnerabilities](vt_ip_vulnerabilities.md)	 - IOC's related vulnerabilities.


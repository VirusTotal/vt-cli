## vt file

Get information about files

### Synopsis

Get information about one or more files.

This command receives one or more hashes (SHA-256, SHA-1 or MD5) and returns
information about the corresponding files. The information for each file appears
in the same order as the hashes are passed to the command.

If the command receives a single hypen (-) the hashes are read from the standard
input, one per line.


```
vt file [hash]... [flags]
```

### Examples

```
  vt file 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
  vt file 76cdb2bad9582d23c1f6f4d868218d6c
  vt file 76cdb2bad9582d23c1f6f4d868218d6c 44d88612fea8a8f36de82e1278abb02f
  cat list_of_hashes | vt file -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for file
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
* [vt file analyses](vt_file_analyses.md)	 - Analyses for the file.
* [vt file associations](vt_file_associations.md)	 - Returns the collections related to the IOC.
* [vt file attack_techniques](vt_file_attack_techniques.md)	 - Returns the Attack Techniques of the File.
* [vt file behaviours](vt_file_behaviours.md)	 - Behaviour reports for the file.
* [vt file bundled_files](vt_file_bundled_files.md)	 - Files bundled within the file.
* [vt file campaigns](vt_file_campaigns.md)	 - IOC's related campaigns.
* [vt file carbonblack_children](vt_file_carbonblack_children.md)	 - Files derived from the file according to Carbon Black.
* [vt file carbonblack_parents](vt_file_carbonblack_parents.md)	 - Files from where the file was derived according to Carbon Black.
* [vt file clues](vt_file_clues.md)	 - Clues for the file.
* [vt file code_blocks](vt_file_code_blocks.md)	 - Code blocks of the file.
* [vt file collections](vt_file_collections.md)	 - Returns the collections related to the IOC.
* [vt file comments](vt_file_comments.md)	 - Comments for the file.
* [vt file compressed_parents](vt_file_compressed_parents.md)	 - Compressed files that contain the file.
* [vt file contacted_domains](vt_file_contacted_domains.md)	 - Domains contacted by the file.
* [vt file contacted_ips](vt_file_contacted_ips.md)	 - IP addresses contacted by the file.
* [vt file contacted_urls](vt_file_contacted_urls.md)	 - URLs contacted by the file.
* [vt file distributors](vt_file_distributors.md)	 - Software marketplaces distributing the file.
* [vt file dropped_files](vt_file_dropped_files.md)	 - Files dropped by the file.
* [vt file email_attachments](vt_file_email_attachments.md)	 - Files attached to the email.
* [vt file email_parents](vt_file_email_parents.md)	 - Email files that contained the file.
* [vt file embedded_domains](vt_file_embedded_domains.md)	 - Domain names embedded in the file.
* [vt file embedded_ips](vt_file_embedded_ips.md)	 - IP addresses embedded in the file.
* [vt file embedded_urls](vt_file_embedded_urls.md)	 - URLs embedded in the file.
* [vt file execution_parents](vt_file_execution_parents.md)	 - Files that executed the file.
* [vt file graphs](vt_file_graphs.md)	 - Graphs that include the file.
* [vt file itw_domains](vt_file_itw_domains.md)	 - In the wild domains from where the file has been downloaded.
* [vt file itw_ips](vt_file_itw_ips.md)	 - In the wild IP addresses from where the file has been downloaded.
* [vt file itw_urls](vt_file_itw_urls.md)	 - In the wild URLs from where the file has been downloaded.
* [vt file malware_families](vt_file_malware_families.md)	 - IOC's related malware families.
* [vt file memory_pattern_domains](vt_file_memory_pattern_domains.md)	 - Domain string patterns found in memory during sandbox execution.
* [vt file memory_pattern_ips](vt_file_memory_pattern_ips.md)	 - IP address string patterns found in memory during sandbox execution.
* [vt file memory_pattern_urls](vt_file_memory_pattern_urls.md)	 - URL string patterns found in memory during sandbox execution.
* [vt file overlay_children](vt_file_overlay_children.md)	 - Files contained by the file as an overlay.
* [vt file overlay_parents](vt_file_overlay_parents.md)	 - Files that contain the file as an overlay.
* [vt file parent_resource_urls](vt_file_parent_resource_urls.md)	 - Returns the URLs where this file has been loaded as resource.
* [vt file pcap_children](vt_file_pcap_children.md)	 - PCAP files seen in the file.
* [vt file pcap_parents](vt_file_pcap_parents.md)	 - PCAP files that contain the file.
* [vt file pe_resource_children](vt_file_pe_resource_children.md)	 - PE files contained by the file as a resource.
* [vt file pe_resource_parents](vt_file_pe_resource_parents.md)	 - PE files containing the file as a resource.
* [vt file references](vt_file_references.md)	 - Returns the References for the file.
* [vt file related_attack_techniques](vt_file_related_attack_techniques.md)	 - Returns the Attack Techniques of the Collections containing this File.
* [vt file related_references](vt_file_related_references.md)	 - Returns Direct References plus References of the Collections containing     this File.
* [vt file related_reports](vt_file_related_reports.md)	 - IOC's related reports
* [vt file related_threat_actors](vt_file_related_threat_actors.md)	 - IOC's related threat actors.
* [vt file relationships](vt_file_relationships.md)	 - Get all relationships.
* [vt file reports](vt_file_reports.md)	 - IOC's related reports.
* [vt file screenshots](vt_file_screenshots.md)	 - Screenshots obtained from the execution of the file.
* [vt file similar_files](vt_file_similar_files.md)	 - Files that are similar to the file, using only VHASH.
* [vt file software_toolkits](vt_file_software_toolkits.md)	 - IOC's related software toolkits.
* [vt file submissions](vt_file_submissions.md)	 - Submissions for the file.
* [vt file urls_for_embedded_js](vt_file_urls_for_embedded_js.md)	 - URLs where this (JS) file is embedded.
* [vt file user_votes](vt_file_user_votes.md)	 - Item's votes made by current signed-in user.
* [vt file votes](vt_file_votes.md)	 - Item's votes.
* [vt file vulnerabilities](vt_file_vulnerabilities.md)	 - IOC's related vulnerabilities.


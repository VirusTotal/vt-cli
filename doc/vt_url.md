## vt url

Get information about URLs

### Synopsis

Get information about one or more URLs.

This command receives one or more URLs and returns information about them. URL
hashes as returned in the "object_id" field are also accepted. The information
about each URL is returned in the same order as the URLs are passed to the
command.

If the command receives a single hypen (-) the URLs are read from the standard
input, one per line.


```
vt url [url]... [flags]
```

### Examples

```
  vt url https://www.virustotal.com
  vt url f1177df4692356280844e1d5af67cc4a9eccecf77aa61c229d483b7082c70a8e
  cat list_of_urls | vt url -
```

### Options

```
  -x, --exclude strings    exclude fields matching the provided pattern
  -h, --help               help for url
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
* [vt url analyses](vt_url_analyses.md)	 - Analyses for the URL.
* [vt url associations](vt_url_associations.md)	 - Returns the collections related to the IOC.
* [vt url campaigns](vt_url_campaigns.md)	 - IOC's related campaigns.
* [vt url collections](vt_url_collections.md)	 - Returns the collections related to the IOC.
* [vt url comments](vt_url_comments.md)	 - Comments for the URL.
* [vt url communicating_files](vt_url_communicating_files.md)	 - Files that communicate with this url when they are executed.
* [vt url contacted_domains](vt_url_contacted_domains.md)	 - Distinct domains from which the URL loads some kind of resource.
* [vt url contacted_ips](vt_url_contacted_ips.md)	 - Distinct IP addresses from which the URL loads some kind of resource.
* [vt url downloaded_files](vt_url_downloaded_files.md)	 - Interesting files downloaded from the URL.
* [vt url embedded_js_files](vt_url_embedded_js_files.md)	 - JS files embedded in a URL.
* [vt url graphs](vt_url_graphs.md)	 - Graphs that include the URL.
* [vt url http_response_contents](vt_url_http_response_contents.md)	 - HTTP response contents from the URL.
* [vt url last_serving_ip_address](vt_url_last_serving_ip_address.md)	 - Last IP address that served the URL.
* [vt url malware_families](vt_url_malware_families.md)	 - IOC's related malware families.
* [vt url memory_pattern_parents](vt_url_memory_pattern_parents.md)	 - Files having a domain as string on memory during sandbox execution.
* [vt url network_location](vt_url_network_location.md)	 - Domain or IP address for the URL.
* [vt url parent_resource_urls](vt_url_parent_resource_urls.md)	 - Returns the URLs where this URL has been loaded as resource.
* [vt url redirecting_urls](vt_url_redirecting_urls.md)	 - URLs that redirected to the given URL.
* [vt url redirects_to](vt_url_redirects_to.md)	 - URLs that this url redirects to.
* [vt url references](vt_url_references.md)	 - Returns the References related to the URL.
* [vt url referrer_files](vt_url_referrer_files.md)	 - Files containing the URL.
* [vt url referrer_urls](vt_url_referrer_urls.md)	 - URLs that refer to the given URL.
* [vt url related_collections](vt_url_related_collections.md)	 - Returns the Collections of the parent Domains or IPs of this URL.
* [vt url related_comments](vt_url_related_comments.md)	 - Comments for the URL.
* [vt url related_references](vt_url_related_references.md)	 - Returns the direct and related references containing this URL.
* [vt url related_reports](vt_url_related_reports.md)	 - IOC's related reports
* [vt url related_threat_actors](vt_url_related_threat_actors.md)	 - IOC's related threat actors.
* [vt url relationships](vt_url_relationships.md)	 - Get all relationships.
* [vt url reports](vt_url_reports.md)	 - IOC's related reports.
* [vt url software_toolkits](vt_url_software_toolkits.md)	 - IOC's related software toolkits.
* [vt url submissions](vt_url_submissions.md)	 - Submissions for the URL.
* [vt url urls_related_by_tracker_id](vt_url_urls_related_by_tracker_id.md)	 - URLs that share the same tracker ID.
* [vt url user_votes](vt_url_user_votes.md)	 - Item's votes made by current signed-in user.
* [vt url votes](vt_url_votes.md)	 - Item's votes.
* [vt url vulnerabilities](vt_url_vulnerabilities.md)	 - IOC's related vulnerabilities.


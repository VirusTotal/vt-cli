# VirusTotal CLI

Welcome to the VirusTotal CLI, a tool designed for those who love both VirusTotal and command-line interfaces. With this tool you can do everything you'd normally do using VirusTotal's web page, including:

* Retrieve information about a [file](doc/vt_file.md), [URL](doc/vt_url.md), [domain name](doc/vt_domain.md), [IP address](doc/vt_ip.md), etc.
* [Search](doc/vt_search.md) for files and URLs using VirusTotal Intelligence query syntax.
* [Download files](doc/vt_download.md).
* [Manage your LiveHunt YARA rules](doc/vt_hunting_ruleset.md).
* [Launch Retrohunt jobs](doc/vt_retrohunt_start.md) and [get their results](doc/vt_retrohunt_matches.md).

And much [more](doc/vt.md)...

## See it in action

[![asciicast](https://asciinema.org/a/179696.png)](https://asciinema.org/a/179696)

## Getting started

As this tool uses the [VirusTotal API](https://docs.virustotal.com/reference) under the hood, you will need a VirusTotal API key. By [signing up](https://www.virustotal.com/#/join-us) with VirusTotal you will receive a free API key however, free API keys have a limited amount of requests per minute, and they don't have access to some premium features like searches and file downloads. If you are interested in using those premium features please [contact us](https://www.virustotal.com/gui/contact-us/).

### Installing the tool

There are two ways of installing the tool: by using one of our pre-compiled binaries or by building it by yourself.

#### Pre-compiled binaries

The pre-compiled binaries can be found on [the releases page](https://github.com/VirusTotal/vt-cli/releases). There are binaries for Windows, Linux and Mac OS X. To use them, just download the file, decompress it and place it in a directory where you think is more convenient to use.

#### Manual building

To compile the program you'll need [Go 1.14.x or higher installed in your system](https://go.dev/doc/install) and type the following commands:

```sh
$ git clone https://github.com/VirusTotal/vt-cli
$ cd vt-cli
$ make install
```

NOTE: in order to use the `vt` binary, make sure the `GOBIN` is part of your `PATH` env variable:

```sh
$ export GOBIN=`go env GOPATH`/bin
$ export PATH=$PATH:$GOBIN
```

##### Mac OS
Download the MacOS package from [the releases page](https://github.com/VirusTotal/vt-cli/releases).  Copy the file to a location in your PATH, then remove the quarantine flag. 

```sh
$ unzip MacOSX.zip
$ mkdir -p $HOME/bin
$ mv vt $HOME/bin
$ export PATH=$PATH:$HOME/bin
$ xattr -d com.apple.quarantine $HOME/bin/vt
```

Alternative solution for Mac OS users, there's a [brew formula](https://formulae.brew.sh/formula/virustotal-cli) available. Please note this is not maintained by VirusTotal.

```sh
$ brew install virustotal-cli
```

##### Windows

For Windows users, there's a [Winget manifest](https://github.com/microsoft/winget-pkgs/tree/master/manifests/v/VirusTotal/vt-cli) available. Please note this is not maintained by VirusTotal.

```powershell
winget install VirusTotal.vt-cli
```

Chocolatey is [also supported](https://community.chocolatey.org/packages/vt-cli) (Also not maintained by VirusTotal):

```powershell
choco install vt-cli
```

### A note on Window's console

If you plan to use `vt-cli` in Windows on a regular basis we highly recommend you avoid the standard Windows console and use [Cygwin](https://www.cygwin.com/) instead. The Windows console is *very* slow when printing large amounts of text (as `vt-cli` usually does) while Cygwin performs much better. Additionally, you can benefit from Cygwin's support for command auto-completion, a handy feature that the Windows console doesn't offer. In order to take advantage of auto-completion make sure to include the `bash-completion` package while installing Cygwin.

### Configuring your API key

Once you have installed the vt-cli tool you may want to configure it with your API key. This is not strictly necessary, as you can provide your API key every time you invoke the tool by using the `--apikey` option (`-k` in short form), but that's a bit of a hassle if you are going to use the tool frequently (and we bet you'll do!). For configuring your API key just type:

```sh
$ vt init
```

This command will ask for your API key, and save it to a config file in your home directory (~/.vt.toml). You can also specify your API key using the  `VTCLI_APIKEY` environment variable. If you specify your API key in multiple ways, the `--apikey` option will have the highest precedence, followed by the `VTCLI_APIKEY` environment variable, the API key in the configuration file will be used as the last resort.

### Use with a proxy

If you are behind an HTTP proxy you can tell `vt-cli` which is the address of your proxy server in multiple ways. One is using the `--proxy` option, like in:

```sh
$ vt --proxy http://myproxy.com:1234 <command>
```

You can also use the `VTCLI_PROXY` environment variable, or add the following line to the config file:

```sh
proxy="http://myproxy.com:1234"
```

### Setup Bash completion

If you are going to use this tool frequently you may want to have command auto-completion. It saves both precious time and keystrokes. Notice however that you must configure your API as described in the previous section *before* following the steps listed below. The API is necessary for determining the commands that you will have access to.

* Linux:

  ```sh
  $ vt completion bash > /etc/bash_completion.d/vt
  ```

* Mac OS X:

  ```sh
  $ brew install bash-completion
  $ vt completion bash > $(brew --prefix)/etc/bash_completion.d/vt
  ```

  Add the  following lines to `~/.bash_profile`:

  ```sh
  if [ -f $(brew --prefix)/etc/bash_completion ]; then
  . $(brew --prefix)/etc/bash_completion
  fi
  ```

* Cygwin:

  Make sure the `bash-completion` package is installed (Cygwin doesn't install it by default) and type:

  ```sh
  $ vt completion bash > /usr/share/bash-completion/completions/vt
  ```

:heavy_exclamation_mark: You may need to restart your shell in order for autocompletion to start working.

### Setup ZSH completion

The output script from `vt completion zsh` needs to be put somewhere under the `$fpath` directory. For example, `.oh-my-zsh/completions` directory:

```shellsession
$ mkdir /Users/$USERNAME/.oh-my-zsh/completions
$ vt completion zsh > /Users/$USERNAME/.oh-my-zsh/completions/_vt
```

Restart the shell.

## Usage examples

* Get information about a file:

  ```sh
  $ vt file 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
  ```

* Get information about a file in JSON format:

  ```sh
  $ vt file 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85 --format json
  ```

* Get a specific analysis report for a file:

  ```sh
  $ # File analysis IDs can be given as `f-<file_SHA256_hash>-<UNIX timestamp>`...
  $ vt analysis f-8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85-1546309359
  $ # ...or as a Base64 encoded string, retrieved from the `vt scan file` command:
  $ vt scan file test.txt
  test.txt MDJiY2FiZmZmZmQxNmZlMGZjMjUwZjA4Y2FkOTVlMGM6MTU0NjQ1NDUyMA==
  $ vt analysis MDJiY2FiZmZmZmQxNmZlMGZjMjUwZjA4Y2FkOTVlMGM6MTU0NjQ1NDUyMA==
  - _id: "MDJiY2FiZmZmZmQxNmZlMGZjMjUwZjA4Y2FkOTVlMGM6MTU0NjQ1NDUyMA=="
    _type: "analysis"
    date: 1546454520  # 2019-01-02 13:42:00 -0500 EST
    stats:
      failure: 0
      harmless: 0
      malicious: 0
      suspicious: 0
      timeout: 0
      type-unsupported: 0
      undetected: 0
    status: "queued"
  ```

* Download files given a list of hashes in a text file, one hash per line:

  ```sh
  $ cat /path/list_of_hashes.txt | vt download -
  ```

* Get information about a URL:

  ```sh
  $ vt url http://www.virustotal.com
  ```

* Get the IP address that served a URL:

  ```sh
  $ vt url last_serving_ip_address http://www.virustotal.com
  ```

* Search for files:

  ```sh
  $ vt search "positives:5+ type:pdf"
  ```
  
* Scan a file:

  ```sh
  $ vt scan file <yourfile>
  <yourfile> ZDZiOTcxY2JhNDE0MWU5ZWRjN2JjNGQ2NTdhN2VjODU6MTU3MDE3Mjg1NQ==
  $ vt analysis ZDZiOTcxY2JhNDE0MWU5ZWRjN2JjNGQ2NTdhN2VjODU6MTU3MDE3Mjg1NQ==
  - _id: "ZDZiOTcxY2JhNDE0MWU5ZWRjN2JjNGQ2NTdhN2VjODU6MTU3MDE3Mjg1NQ=="
    _type: "analysis"
    date: 1570172855  # 2019-10-04 09:07:35 +0200 CEST
    stats:
      failure: 0
      harmless: 0
      malicious: 0
      suspicious: 0
      timeout: 0
      type-unsupported: 0
      undetected: 0
    status: "queued"
  ```

* Export detections and tags of files from a search in CSV format:

  ```sh
  $ vt search "positives:5+ type:pdf" -i sha256,last_analysis_stats.malicious,tags --format csv
  ```

* Export detections and tags of files from a search in JSON format:

  ```sh
  $ vt search "positives:5+ type:pdf" -i sha256,last_analysis_stats.malicious,tags --format json
  ```

## Getting only what you want

When you ask for information about a file, URL, domain, IP address or any other object in VirusTotal, you get a lot of data (by default in YAML format) that is usually more than what you need. You can narrow down the information shown by the vt-cli tool by using the `--include` and `--exclude` command-line options (`-i` and `-x` in short form).

These options accept patterns that are matched against the fields composing the data, and allow you to include only a subset of them, or exclude any field that is not interesting for you. Let's see how it works using the data we have about `http://www.virustotal.com` as an example:

```sh
$ vt url http://www.virustotal.com
- _id: 1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31
  _type: "url"
  first_submission_date: 1275391445  # 2010-06-01 13:24:05 +0200 CEST
  last_analysis_date: 1532442650  # 2018-07-24 16:30:50 +0200 CEST
  last_analysis_results:
    ADMINUSLabs:
      category: "harmless"
      engine_name: "ADMINUSLabs"
      result: "clean"
    AegisLab WebGuard:
      category: "harmless"
      engine_name: "AegisLab WebGuard"
      result: "clean"
    AlienVault:
      category: "harmless"
      engine_name: "AlienVault"
      result: "clean"
  last_http_response_code: 200
  last_http_response_content_length: 7216
  last_http_response_content_sha256: "7ed66734d9fb8c5a922fffd039c1cd5d85f8c2bb39d14803983528437852ba94"
  last_http_response_headers:
    age: "26"
    cache-control: "public, max-age=60"
    content-length: "7216"
    content-type: "text/html"
    date: "Tue, 24 Jul 2018 14:30:24 GMT"
    etag: "\"bGPKJQ\""
    expires: "Tue, 24 Jul 2018 14:31:24 GMT"
    server: "Google Frontend"
    x-cloud-trace-context: "131ac6cb5e2cdb7970d54ee42fd5ce4a"
    x-frame-options: "DENY"
  last_submission_date: 1532442650  # 2018-07-24 16:30:50 +0200 CEST
  private: false
  reputation: 1484
  times_submitted: 213227
  total_votes:
    harmless: 660
    malicious: 197
```

Notice that the returned data usually follows a hierarchical structure, with some top-level fields that may contain subfields which in turn can contain their own subfields. In the example above `last_http_response_headers` has subfields `age`, `cache-control`, `content-length` and so on, while `total_votes` has `harmless` and `malicious`. For referring to a particular field within the hierarchy we can use a path, similar to how we identify a file in our computers, but in this case, we are going to use a dot character (.) as the separator for path components, instead of the slashes (or backslashes) used by most file systems. The following ones are valid paths for our example structure:

* `last_http_response_headers.age`
* `total_votes.harmless`
* `last_analysis_results.ADMINUSLabs.category`
* `last_analysis_results.ADMINUSLabs.engine_name`

The filters accepted by both `--include` and `--exclude` are paths in which we can use `*` and `**` as placeholders for one and many path elements respectively. For example `foo.*` matches `foo.bar` but not `foo.bar.baz`, while `foo.**` matches `foo.bar`, `foo.bar.baz` and `foo.bar.baz.qux`. In the other hand, `foo.*.qux` matches `foo.bar.qux` and `foo.baz.qux` but not `foo.bar.baz.qux`, while `foo.**.qux` matches
`foo.bar.baz.qux` and any other path starting with `foo` and ending with `qux`.

For cherry-picking only the fields you want, you should use `--include` followed by a path pattern as explained above. You can also include more than one pattern either by using the `--include` argument multiple times, or by using it with a comma-separated list of patterns. The following two options are equivalent:

```sh
$ vt url http://www.virustotal.com --include=reputation --include=total_votes.*
$ vt url http://www.virustotal.com --include=reputation,total_votes.*
```

Here you have different examples with their outputs (assuming that `vt url http://www.virustotal.com` returns the structure shown above):

```sh
$ vt url http://www.virustotal.com --include=last_http_response_headers.server
- last_http_response_headers:
    server: "Google Frontend"
```

```sh
$ vt url http://www.virustotal.com --include=last_http_response_headers.*
- last_http_response_headers:
    age: "26"
    cache-control: "public, max-age=60"
    content-length: "7216"
    content-type: "text/html"
    date: "Tue, 24 Jul 2018 14:30:24 GMT"
    etag: "\"bGPKJQ\""
    expires: "Tue, 24 Jul 2018 14:31:24 GMT"
    server: "Google Frontend"
    x-cloud-trace-context: "131ac6cb5e2cdb7970d54ee42fd5ce4a"
    x-frame-options: "DENY"
```

```sh
$ vt url http://www.virustotal.com --include=last_analysis_results.**
- last_analysis_results:
    ADMINUSLabs:
      category: "harmless"
      engine_name: "ADMINUSLabs"
      result: "clean"
    AegisLab WebGuard:
      category: "harmless"
      engine_name: "AegisLab WebGuard"
      result: "clean"
    AlienVault:
      category: "harmless"
      engine_name: "AlienVault"
      result: "clean"
```

```sh
$ vt url http://www.virustotal.com --include=last_analysis_results.*.result
- last_analysis_results:
    ADMINUSLabs:
      result: "clean"
    AegisLab WebGuard:
      result: "clean"
    AlienVault:
      result: "clean"
```

```sh
$ vt url http://www.virustotal.com --include=**.result
- last_analysis_results:
    ADMINUSLabs:
      result: "clean"
    AegisLab WebGuard:
      result: "clean"
    AlienVault:
      result: "clean"
```

Also notice that `_id` and `_type` are also field names and therefore you can use them in your filters:

```sh
$ vt url http://www.virustotal.com --include=_id,_type,**.result
- _id: "1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31"
  _type: "file"
  last_analysis_results:
    ADMINUSLabs:
      result: "clean"
    AegisLab WebGuard:
      result: "clean"
    AlienVault:
      result: "clean"
```

The `--exclude` option works similarly to `--include` but instead of including the matching fields in the output, it includes everything except the matching fields. You can use this option when you want to keep most of the fields, but leave out a few of them that are not interesting. If you use `--include` and `--exclude` simultaneously `--include` enters in action first, including only the fields that match the `--include` patterns, while `--exclude` comes in after that, removing any remaining field that matches the `--exclude` patterns.

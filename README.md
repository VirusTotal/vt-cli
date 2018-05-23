# VirusTotal CLI

Welcome to the VirusTotal CLI, a tool designed for those of you who love both VirusTotal and command-line interfaces. With this tool you can do everything you'd normally do using the VirusTotal's web page, including:

* Retrieve information about a file, URL, domain name, IP address, etc.
* Search for files using VirusTotal Intelligence query syntax.
* Download files.
* Manage your Malware Hunting YARA rules.
* Launch Retrohunt jobs and get their results.

## See it in action

[![asciicast](https://asciinema.org/a/179696.png)](https://asciinema.org/a/179696)

## Getting started

As this tool use the [VirusTotal API](https://developers.virustotal.com/v3.0/reference) under the hood, you will need a VirusTotal API key. By [signing-up](https://www.virustotal.com/#/join-us) with VirusTotal you will receive a free API key, however free API keys have a limited amount of requests per minute, and they don't have access to some premium features like searches and file downloads. If you are interested in using those premium features please [contact us](https://support.virustotal.com/hc/en-us/requests/new).

### Installing the tool

For installing the tool you can download one the [pre-compiled binaries](https://github.com/VirusTotal/vt-cli/releases) we offer for the most popular operating systems, or alternatively you can compile it yourself from source code. For compiling the program you'll need Go 1.9.x or higher installed in your system and type the following commands:

```
$ go get -u github.com/golang/dep/cmd/dep
$ go get -d github.com/VirusTotal/vt-cli/vt
$ cd `go env GOPATH`/src/github.com/VirusTotal/vt-cli
$ dep ensure
$ make install
```

### Configuring your API key

Once you have installed the vt-cli tool you may want to configure it with your API key. This is not strictly necessary, as you can provide your API key every time you invoke the tool by using the `--apikey` option (`-k` in short form), but that's a bit of a hassle if you are going to use the tool frequently (and we bet you'll do!). For configuring your API key just type:

```
$ vt init
```

This command will ask for your API key, and save it to a config file in your home directory (~/.vt.toml)

### Setup Bash completion

If you are going to use this tool frequently you may want to have command auto-completion, as it saves both precious time and keystrokes. Follow these instructions to enable Bash completion:

* Linux:
	```
	$ vt completion bash > /etc/bash_completion.d/vt
	```
	
* Mac OS X:
	```
	$ brew install bash-completion
	$ vt completion bash > $(brew --prefix)/etc/bash_completion.d/vt
	```
	Add the  following lines to `~/.bash_profile`
    ```
	if [ -f $(brew --prefix)/etc/bash_completion ]; then
	. $(brew --prefix)/etc/bash_completion
	fi
	```

## Usage examples

* Get information about a file:
	```
	$ vt file 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
	```

* Download files given a list of hashes in a text file, one hash per line:
	```
	$ cat /path/list_of_hashes.txt | vt download -  
	```
	
* Search for files:
	```
	$ vt search "positives:5+ type:pdf"  
	```

# cs_parser_test

Small utility to allow simpler, quicker testing of parsing files in [crowdsec](https://crowdsec.net/) 

## Usage

```
$ sudo cs_parser_test -t syslog /var/log/mail.log
```

NB No changes to the running instance are made.

Essentially you need to supply the same data you would enter into the acquis.yaml file. The above would be shown as

```
---
# postfix
filenames:
  - /var/log/mail.log
labels:
  type: syslog
```

One of the intents of wriing the app was to allow me to test different parsers without needing to contiually alter the running instance or the acquis.yaml file. So to test a parser for my postfix logs I can add the parser and then run the app with a different type specified.

By default this will now load the scenarios and show which ones would handle each line.

The output can get quite long, so careful use of the -n flag is advised!

```
$ sudo ./cs_parser_test -type postfix -n 1 /var/log/mail.log
Processing file /var/log/mail.log
Configuration from /etc/crowdsec/config.yaml

INFO[0000] Loading grok library /etc/crowdsec/patterns/ 
INFO[0000] Loading enrich plugins                       
INFO[0000] Loading parsers 11 stages                    
INFO[0000] Loaded 1 parser nodes                         file=/etc/crowdsec/parsers/s02-enrich/http-logs.yaml
INFO[0000] Loaded 1 parser nodes                         file=/etc/crowdsec/parsers/s01-parse/postscreen-logs.yaml
...
INFO[0000] Loaded 12 nodes, 3 stages                    
INFO[0000] Loading postoverflow Parsers                 
INFO[0000] Loaded 0 nodes, 0 stages                     
Scenario: crowdsecurity/http-backdoors-attempts
INFO[0000] Adding leaky bucket                           cfg= file=/etc/crowdsec/scenarios/http-backdoors-attempts.yaml name=crowdsecurity/http-backdoors-attempts
    loaded OK
/etc/crowdsec/scenarios/http-backdoors-attempts.yaml
  Scenario: crowdsecurity/http-xss-probbing
INFO[0000] Adding leaky bucket                           cfg= file=/etc/crowdsec/scenarios/http-xss-probing.yaml name=crowdsecurity/http-xss-probbing
    loaded OK
/etc/crowdsec/scenarios/http-xss-probing.yaml
  Scenario: crowdsecurity/iptables-scan-multi_ports
INFO[0000] Adding leaky bucket                           cfg= file=/etc/crowdsec/scenarios/iptables-scan-multi_ports.yaml name=crowdsecurity/iptables-scan-multi_ports
    loaded OK
...

Scanning file until 1 match is found...

Line 32:
  Processed? true
  Final Stage: s02-enrich
  Parsed Entries [evt.Parsed]:
    message             : Jul 12 06:26:10 xxxxxxx: warning: unknown[111.17.201.197]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
    program             : postfix
    remote_addr         : 111.17.201.197
    message_failure     :  UGFzc3dvcmQ6
    remote_host         : unknown
Metadata [evt.Meta]:
    log_type_enh        : spam-attempt
    service             : postfix
    source_ip           : 111.17.201.197
    log_type            : postfix
    IsoCode             : CN
    ASNNumber           : 24444
    SourceRange         : 111.16.0.0/15
    source_hostname     : unknown
    IsInEU              : false
    ASNOrg              : Shandong Mobile Communication Company Limited



Scanned a total of 32 lines to find 1 matches
```

## Command Options

```
$ ./cs_parser_test -h
Usage of ./cs_parser_test:
  -all
        show all line results (verbose)
  -c string
        configuration file to use (default "/etc/crowdsec/config.yaml")
  -n int
        how many lines to show (default: 0, unlimited)
  -parse
        parse ONLY. no scenarios loaded
  -type string
        type to assign (default "syslog")
```

## Why?

The [Crowdsec](https://github.com/crowdsecurity/crowdsec) project has a great and very responsive development team but they are developing their product quickly and there have been a lot of large changes since I started using it. As I evolved my parsers I found it hard at times to figure out whether the change was correct or not. This small app is designed to allow me to develop the parsers and scenarios further while quickly test against a file.

Maybe it'll be of use to others?

## Future

Likely the next change will be to add a way to use the app to create a sample log file to parse by saving all the lines that match into a new file. This should assist with debugging by providing a richer dataset.

Patches, corrections and improvements always welcome.
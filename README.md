# sipit

A simple but powerful command line interface for the [Simple Indicator Platform](https://github.com/ace-ecosystem/sip). It's simple indicator management from the command line.

Integrates with [sipwhitelist](https://github.com/ace-ecosystem/sipwhitelist) and is built using [pysip](https://github.com/ace-ecosystem/pysip).

~/.sipit.ini is required with the following configurations:
```
[sip]
; user that will be assigned when creating the indicator
user = rockstar5
; SIP endpoint
end_point = sip.yourdomain:4443
; api_key from SIP
api_key = 5b311126-65a1-2957-96c8-b00c5ca296dc
```

Usage:

```
usage: sipit.py [-h] [-d] [-e {default}]
                {whitelist,query,update,bulk_create,create,delete} ...

Add Indicators and query SIP

positional arguments:
  {whitelist,query,update,bulk_create,create,delete}
    whitelist           Check values against a SIP Whitelist instance.
    query               query aspects of SIP. query -h for more
    update              update indicator attributes. update -h for more
    bulk_create         add indicators from a json file to SIP. IOC-Parser can
                        be used to create the json file. create_bulk -h for
                        more
    create              add indicator to SIP. create -h for more
    delete              Delete a SIP indicator.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn on debug logging.
  -e {default}, --enviro {default}
                        the SIP environment to work with
```

Query usage:

```
usage: sipit query [-h] [-t] [-s] [-c] [--tags] [-v VALUE] [-ev EXACT_VALUE]
                   [-d] [--status] [-id ID] [-w]

optional arguments:
  -h, --help            show this help message and exit
  -t, --types           list indicator types
  -s, --sources         list sources
  -c, --campaigns       list campaigns
  --tags                list tags
  -v VALUE, --value VALUE
                        search for indicators containing this value
  -ev EXACT_VALUE, --exact_value EXACT_VALUE
                        search for an indicator with this exact value.
  -d, --details         all information about an indicator value
  --status              list possible status values for indicators
  -id ID, --indicator-id ID
                        query the specific indicator information for a sip id
  -w, --whitelist-info  List the configured SIP whitelist.
```

Query for an indicator value in all indicators:

```
$ sipit query -v 'yo<font'
---> 278582 | ils to yo<font | String - HTML | Analyzed
```

Query for an exact indicator value:

```
$ sipit query -ev 'ils to yo<font'
---> 278582 | ils to yo<font | String - HTML | Analyzed
```

Query for an indicator by id:

```
$ sipit query  -i 278582
---> 278582 | ils to yo<font | String - HTML | Analyzed

```

Create a &#127866;indicator:
```
$ sipit.py create -t String\ -\ HTML -v '&#127866;' --source OSINT -r 'https://github.com/ace-ecosystem/sipwhitelist/blob/master/README.md' --tags beer_emoji,example

{'all_children': [],
 'all_equal': [],
 'campaigns': [],
 'case_sensitive': False,
 'children': [],
 'confidence': 'unknown',
 'created_time': 'Tue, 31 Mar 2020 22:02:48 GMT',
 'equal': [],
 'id': 280940,
 'impact': 'unknown',
 'modified_time': 'Tue, 31 Mar 2020 22:04:02 GMT',
 'parent': None,
 'references': [{'id': 12536,
                 'reference': 'https://github.com/ace-ecosystem/sipwhitelist/blob/master/README.md',
                 'source': 'OSINT',
                 'user': 'smcfeely'}],
 'status': 'Analyzed',
 'substring': False,
 'tags': ['beer_emoji', 'example'],
 'type': 'String - HTML',
 'user': 'smcfeely',
 'value': '&#127866;'}
```

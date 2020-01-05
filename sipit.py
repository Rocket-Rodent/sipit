#!/usr/bin/env python3
# https://argcomplete.readthedocs.io/en/latest/#global-completion
# PYTHON_ARGCOMPLETE_OK

import pysip
import argparse
import argcomplete
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import json
import pprint
import logging
import yaml

from sipwhitelist import SIPWhitelist

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
# set noise level
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)


DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), '.config', 'sipit.yaml')


def create_default_user_config(server, port, user, api_key, whitelist_tags=[], ignore_proxy=True, verify_ssl=False):
    """Creates a minimal configuration for the user.
    """
    config = {}
    config_path = DEFAULT_CONFIG_PATH
    config['default'] = {'server': server,
                         'port': port,
                         'user': user,
                         'api_key': api_key,
                         'whitelist_tags': whitelist_tags,
                         'ignore_proxy': ignore_proxy,
                         'verify_ssl': verify_ssl}
    with open(config_path, 'w') as configfile:
        #config.write(configfile)
        yaml.dump(config, configfile, Dumper=Dumper)
    logging.info("Wrote user configuration to: {}".format(config_path))
    return


def load_config(config_path=DEFAULT_CONFIG_PATH,
                required_env_keys=['server',
                                   'port',
                                   'user',
                                   'api_key',
                                   'whitelist_tags',
                                   'ignore_proxy',
                                   'verify_ssl'],
                environment='default'):
    config = None
    try:
        with open(config_path) as c:
           config = yaml.load(c, Loader=Loader)
    except:
        logging.exception("Problem loading config: {}".format(config_path))
        return False
    if config is None:
        return None
    if environment not in config.keys():
        logging.error("'{}' not a configured SIP environment in {}".format(environment, config_path))
        return False
    env_config = config[environment]
    missing_keys = [key for key in required_env_keys if key not in env_config]
    if missing_keys:
        for key in missing_keys:
            logging.error("Missing required key in '{}' configuration: {}".format(environment, key))
        return False
    return config


if __name__ == "__main__":

   default_config_path = DEFAULT_CONFIG_PATH
   if not os.path.exists(default_config_path):
       print("Did not find user configuration at '{}'".format(default_config_path))
       set_config = input("Would you like to create a default sipit config? [Y/n] ") or 'Y'
       if set_config.upper() == 'Y':
           server = input("FQDN of your SIP server: ")
           port = input("Port to connect to your SIP server on? [443] ") or '443'
           user = input("Your SIP username: ")
           api_key = input("Your SIP API Key: ")
           whitelist_tags = input("Comma seperated list of Deprecated SIP Indicator tags for building a sipwhitelist: [whitelist:e2w] ") or 'whitelist:e2w'
           whitelist_tags = whitelist_tags.split(',')
           ignore_proxy = input("Do you need to use the system proxy to connect to the sandbox? [y/N] ") or 'N'
           ignore_proxy = True if ignore_proxy.upper() == 'N' else False
           verify_ssl =  input("Should SSL be verified? [y/N] ") or 'N'
           verify_ssl = False if verify_ssl.upper() == 'N' else True
           if verify_ssl:
               verify_ssl = input("Should the system certificate store be used for verification? [Y/n]") or 'Y'
               if verify_ssl.upper() == 'N':
                   verify_ssl = input("Provide the path to the CA certificate that should be used for verification: ")
                   if not os.path.exists(verify_ssl):
                       print("Path to '{}' does not exist. Try again.".format(verify_ssl))
               else:
                   verify_ssl = True
           create_default_user_config(server, port, user, api_key, whitelist_tags, ignore_proxy, verify_ssl)
       else:
           sys.exit()

   # load default config
   config = load_config()
   if not config:
       logging.error("Problem loading config: {}".format(default_config_path))
       sys.exit(1)

   # get default config items
   server = config['default']['server']
   port = config['default']['port']
   api_key = config['default']['api_key']
   verify_ssl = config['default']['verify_ssl']
   whitelist_tags = config['default']['whitelist_tags']
   ignore_proxy = config['default']['ignore_proxy']

   if ignore_proxy:
       if 'https_proxy' in os.environ:
           del os.environ['https_proxy']
       if 'http_proxy' in os.environ:
           del os.environ['http_proxy']

   # create sip client and sipwhitelist instance
   sip_client = pysip.Client(server+':'+port , api_key, verify=verify_ssl)
   swl = SIPWhitelist(whitelist_tags, sip_client)

   indicator_types = [i['value'] for i in sip_client.get('/api/indicators/type')]
   istatus_types = [s['value'] for s in sip_client.get('/api/indicators/status')]
   isources = [s['value'] for s in sip_client.get('/api/intel/source')]
   whitelisted_itypes = swl.whitelist.keys()
   
   parser = argparse.ArgumentParser(description="Add Indicators and query SIP")
   parser.add_argument('-d', '--debug', default=False, action='store_true', help="Turn on debug logging.")
   parser.add_argument('-e', '--enviro', default='default', action='store', choices=config.keys(), help="the SIP environment to work with")

   subparsers = parser.add_subparsers(dest='command')

   wl_parser = subparsers.add_parser('whitelist', help='Check values against a SIP Whitelist instance.')
   wl_parser.add_argument('value', action='store', help='the value of an existing or would be indicator')
   wl_parser.add_argument('-t', '--types', action='append', choices=whitelisted_itypes, default=[], help='the type of indicator the value(s). You can specify as many as you want. Default is all indicator types.')
   wl_parser.add_argument('-v', '--verbose_check', action='store_true', default=False, help="Check the entire whitelist and return all matches instead of return on first match.")
   #wl_parser.add_argument('-vni', '--value_not_in_indicator', action='store_true', default=False,
   #                            help="value_in_indicator is set to true by default. Set this to turn the bahavior off.")
   #wl_parser.add_argument('-iv', '--indicator_in_value', action='store_true', default=False, help='Turn on sipwhitelist indicator_in_value logic')
   #wl_parser.add_argument('--use-cache', action='store_true', default=False, help='use the sip whitelist cache.')

   query_parser = subparsers.add_parser('query',help="query aspects of SIP. query -h for more")
   query_parser.add_argument('-t','--types',default=False,action='store_true',help='list indicator types')
   query_parser.add_argument('-s','--sources',default=False,action='store_true',help='list sources')
   query_parser.add_argument('-c','--campaigns',default=False,action='store_true',help='list campaigns')
   query_parser.add_argument('--tags',default=False,action='store_true',help='list tags')
   query_parser.add_argument('-v','--value',default=False,dest='value',help='search for indicators containing this value')
   query_parser.add_argument('-ev', '--exact_value', action='store', help='search for an indicator with this exact value.')
   query_parser.add_argument('-d','--details',default=False,action='store_true',help='all information about an indicator value')
   query_parser.add_argument('--status',default=False,action='store_true',help='list possible status values for indicators')
   query_parser.add_argument('-id','--indicator-id',dest='id',help='query the specific indicator information for a sip id')
   query_parser.add_argument('-w', '--whitelist-info', dest='whitelist', action='store_true', help="List the configured SIP whitelist.")

   update_parser = subparsers.add_parser('update',help='update indicator attributes. update -h for more')
   update_parser.add_argument('-s','--status',dest='status',choices=istatus_types, help='update status: query --status for list of status')
   update_parser.add_argument('id',help='id of indicator to update - find id by searching indicator - query -v <indvalue>')
   update_parser.add_argument('-rt', '--remove_tag', dest='remove_tags', action='append', default=[], help="A tag you want to remove from this indicator. Can be specified multiple times.")
   update_parser.add_argument('-t', '--add_tag', dest='add_tags', action='append', default=[], help="Add a tag to this indicator. Can be specified multiple times.")

   bulk_json = subparsers.add_parser('bulk_create',help="add indicators from a json file to SIP. IOC-Parser can be used to create the json file. create_bulk -h for more",
           epilog="python3 sipit.py bulk_create -f /path/to/json/file")
   bulk_json.add_argument('-f','--file',required=True,dest='bulk_json',
      help='take the output of ioc-parser json format and upload the indicators into sip')

   create_parser = subparsers.add_parser('create',help="add indicator to SIP. create -h for more",
           epilog="python3 sipit.py create -t 'String - PE' -r 'http://mycoollink' --tags 'malz,phish,stuff' -v 'something.pdb'")
   create_parser.add_argument('-s','--status',default='New',dest='status',choices=istatus_types,
      help="Status of the indicator to add")
   create_parser.add_argument('-t','--indicator-type',required=True,dest='type',choices=indicator_types,
      help="indicator type (URI - Path, String - PE, etc)")
   create_parser.add_argument('--campaign',dest='campaign',
      help="Campaign (APT32 or Oilrig)")
   create_parser.add_argument('--confidence',default='unknown',dest='confidence',
      help="Indicator Confidence Level")
   create_parser.add_argument('--impact',default='unknown',dest='impact',
      help="Indicator Impact")
   create_parser.add_argument('-v','--value',required=True,dest='value',
      help="Indicator Value")
   create_parser.add_argument('-r','--reference',required=True,dest='reference',
      help="Reference from where the indicator came from - context reference")
   create_parser.add_argument('--tags',dest='tags',
      help="comma delimited tags")
   create_parser.add_argument('--source',default="OSINT",dest='source', choices=isources,
      help="source of the info - OSINT, etc")

   delete_parser = subparsers.add_parser('delete', help="Delete a SIP indicator.")
   delete_parser.add_argument('id', help="The ID of the SIP indicator you want to delete.")

   argcomplete.autocomplete(parser)
   args = parser.parse_args()

   if args.debug:
      logging.getLogger().setLevel(logging.DEBUG)

   if args.enviro and args.enviro != 'default':
       sip_client = pysip.Client(config[args.enviro]['end_point'],
                                 config[args.enviro]['api_key'],
                                 verify=config[args.enviro]['verify_ssl'])
       swl = SIPWhitelist(config[args.enviro][whitelist_tags], sip_client)

   def print_whitelist_results(results):
      """Dict with indicator_type keys, and list of (thing, whitelist_indicator_value) results.
      """
      if results:
         print("WHITELISTED:")
      for result in results:
         print("\t{}:".format(result))
         for whitelist_match in results[result]:
            indicator_id = sip_client.get('indicators?exact_value={}'.format(whitelist_match[1]))[0]['id']
            print("\t\t '{}' whitelisted because of '{}' (ID:{})".format(whitelist_match[0], whitelist_match[1], indicator_id))

   if args.command == 'whitelist':
      if args.types == []:
         args.types = whitelisted_itypes
      whitelisted_str = "WHITELISTED: {} ---> {}"
      for itype in args.types:
         if itype == 'Address - ipv4-addr':
            result, ivalue = swl.is_ip_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Email - Address':
            result = swl.is_email_address_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Email - Subject':
            result = swl.is_email_subject_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Hash - MD5':
            result = swl.is_md5_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Hash - SHA1':
            result = swl.is_sha1_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Hash - SHA256':
            result = swl.is_sha256_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Hash - SSDEEP':
            result = swl.is_ssdeep_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'URI - Domain Name':
            #value_in_indicator = True if args.value_not_in_indicator else False
            result = swl.is_domain_whitelisted(args.value, verbose_check=args.verbose_check)#, value_in_indicator=value_in_indicator, indicator_in_value=args.indicator_in_value)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                  print(whitelisted_str.format(itype, args.value))
         elif itype == 'URI - Path':
            result = swl.is_uri_path_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'URI - URL':
            result = swl.is_url_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Windows - FileName':
            result = swl.is_file_name_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         elif itype == 'Windows - FilePath':
            result = swl.is_file_path_whitelisted(args.value, verbose_check=args.verbose_check)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         else:
            if itype not in whitelisted_itypes:
                logging.warning('Unknown indicator type for whitelist: {}'.format(itype))
            result = swl._is_whitelisted(args.value, [itype], verbose_check=args.verbose_check)#, value_in_indicator=value_in_indicator, indicator_in_value=args.indicator_in_value)
            if result:
               if isinstance(result, dict):
                  print_whitelist_results(result)
               else:
                   print(whitelisted_str.format(itype, args.value))
         #if swl.cache_whitelisted:
         #   print(swl.cache_whitelisted)


   if args.command == 'query':
      if args.types:
         for i in indicator_types:
            print(i)
         sys.exit()
      if args.sources:
         results = sip_client.get('/api/intel/source')
      if args.campaigns:
         results = sip_client.get('/api/campaigns')
         for x in results:
            print("{} - {}".format(x['name'],x['aliases']))
         sys.exit()
      if args.tags:
         results = sip_client.get('/api/tags')
      if args.status:
         results = sip_client.get('/api/indicators/status')
      if args.id:
         x = sip_client.get('/api/indicators/{}'.format(args.id))
         if args.details:
            pprint.pprint(x)
         else:
            print("---> {} | {} | {} | {}".format(x['id'],x['value'],x['type'],x['status']))
         sys.exit()
      if args.value or args.exact_value:
         if args.value:
            results = sip_client.get('indicators?value={}'.format(args.value))
         if args.exact_value:
            results = sip_client.get('indicators?exact_value={}'.format(args.exact_value))
         for x in results:
            if args.details:
               pprint.pprint(sip_client.get('indicators/{}'.format(x["id"])))
            else:
               ind = sip_client.get('indicators/{}'.format(x["id"]))
               #print(ind)
               tmpsrc = []
               tmpref = []
               for r in ind['references']:
                  tmpsrc.append(r['source'])
                  tmpref.append(r['reference'])
               #print("---> {} | {} | {} | {} | {} | {}".format(x['id'],x['value'],x['type'],tmpref,tmpsrc,x['user'],x['created_time'],x['tags']))
               print("---> {} | {} | {} | {}".format(ind['id'],ind['value'],ind['type'],ind['status']))
         sys.exit()
      if args.whitelist:
          for itype in swl.whitelist:
              for indicator in swl.whitelist[itype]:
                  print("---> {} | {}".format(itype, indicator))
          sys.exit()

      for x in results:
         print(x['value'])
      sys.exit()

   if args.command == 'bulk_create':
       if args.bulk_json:
           print("using {} to create indicators".format(args.bulk_json))
           with open(args.bulk_json) as f:
              data = json.load(f)
              for indicator in data['indicators']:
                 try:
                    result = sip_client.post('/api/indicators', indicator)
                    print(result)
                 except pysip.pysip.ConflictError:
                    pass

   if args.command == 'update':
      data = {}
      indicator = sip_client.get('/api/indicators/{}'.format(args.id))
      tags = indicator['tags']
      tags_updated = False
      if len(tags) > 0:
         for tag in args.remove_tags:
            if tag in indicator['tags']:
               print("removing tag from indicator: {}".format(tag))
               indicator['tags'].remove(tag)
               tags_updated = True
         for tag in args.add_tags:
            if tag not in indicator['tags']:
               print("Adding tag to indicator: {}".format(tag))
               tags.append(tag)
               tags_updated = True
         if len(tags) == 0:
            logging.warning("Empty list is not handled by SIP API. Will cause schema: [] is too short. Putting in 'sipit-exception-tag:remove me'")
            tags.append('sipit-exception-tag:remove-me')
      else:
         for tag in args.add_tags:
            if tag not in indicator['tags']:
               print("Adding tag to indicator: {}".format(tag))
               tags.append(tag)
               tags_updated = True
      if tags_updated:
         # Only include tags if something changed
         data['tags'] = tags
      if args.status:
         if args.status == indicator['status']:
            print("Status is already set to {}".format(args.status))
         else:
           print("updating status of {} to {}".format(args.id,args.status))
           data['status'] = args.status
      if data:
         print(data)
         results = sip_client.put('/api/indicators/{}'.format(args.id),data)
         pprint.pprint(results)
      else:
         print("Nothing to update.")

 

   if args.command == 'create':
      user = config[args.enviro]['user']

      data = { 'type' : args.type,
            'status' : args.status,
            'confidence' : args.confidence,
            'impact' : args.impact,
            'value' : args.value,
            'references' : [ {'source':args.source,'reference':args.reference}],
            'username' : user,
            'case_sensitive':False
      }
      if args.tags:
         data['tags'] = args.tags.split(',')
      if args.campaign:
         data['campaigns'] = [ args.campaign ]
   
      print(data)
      print(sip_client.post('/api/indicators',data))

   if args.command == 'delete':
      print(sip_client.delete(args.id))

#!/usr/bin/python3
import pysip
import argparse
from configparser import ConfigParser
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import json

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



if __name__ == "__main__":
   # remove proxy if it's set
   if 'http_proxy' in os.environ:
      del os.environ['http_proxy']
   if 'https_proxy' in os.environ:
      del os.environ['https_proxy']
   # load configuration
   config = ConfigParser()
   config.read(os.path.expanduser("~")+'/.sipit.ini')

   sip_client = pysip.Client(config['sip']['end_point'],config['sip']['api_key'],verify=False)
   parser = argparse.ArgumentParser(description="Add Indicators and query SIP")
   subparsers = parser.add_subparsers(dest='command')
   commands = [ 'create', 'query','update' ]

   query_parser = subparsers.add_parser('query',help="query aspects of SIP. query -h for more")
   query_parser.add_argument('-t','--types',default=False,action='store_true',help='list indicator types')
   query_parser.add_argument('-s','--sources',default=False,action='store_true',help='list sources')
   query_parser.add_argument('-c','--campaigns',default=False,action='store_true',help='list campaigns')
   query_parser.add_argument('--tags',default=False,action='store_true',help='list tags')
   query_parser.add_argument('-v','--value',default=False,dest='value',help='search for an indicator value')
   query_parser.add_argument('-d','--details',default=False,action='store_true',help='all information about an indicator value')
   query_parser.add_argument('--status',default=False,action='store_true',help='list possible status values for indicators')
   query_parser.add_argument('-id','--indicator-id',dest='id',help='query the specific indicator information for a sip id')


   update_parser = subparsers.add_parser('update',help='update indicator attributes. update -h for more')
   update_parser.add_argument('-s','--status',dest='status',help='update status: query --status for list of status')
   update_parser.add_argument('-i','--id',dest='id',required=True,help='id of indicator to update - find id by searching indicator - query -v <indvalue>')

   bulk_json = subparsers.add_parser('bulk_create',help="add indicators from a json file to SIP. IOC-Parser can be used to create the json file. create_bulk -h for more",
           epilog="python3 sipit.py bulk_create -f /path/to/json/file")
   bulk_json.add_argument('-f','--file',required=True,dest='bulk_json',
      help='take the output of ioc-parser json format and upload the indicators into sip')

   create_parser = subparsers.add_parser('create',help="add indicator to SIP. create -h for more",
           epilog="python3 sipit.py create -t 'String - PE' -r 'http://mycoollink' --tags 'malz,phish,stuff' -v 'something.pdb'")
   create_parser.add_argument('-s','--status',default='New',dest='status',
      help="Status of the indicator to add - New, Analyzed, Informational, Deprecated")
   create_parser.add_argument('-t','--indicator-type',required=True,dest='type',
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
   create_parser.add_argument('--source',default="OSINT",dest='source',
      help="source of the info - OSINT, DSIE, RCISC, etc")


   args = parser.parse_args()

   if args.command is None:
      print("\n\n*****")
      print("You must specify one of the following commands:\n")
      print(cbinterface_commands)
      print("\n*****\n\n")
      parser.parse_args(['-h'])

   if args.command == 'query':
      if args.types:
         results = sip_client.get('/api/indicators/type')   
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
            print(x)
         else:
            print("---> {} | {} | {} | {}".format(x['id'],x['value'],x['type'],x['status']))
         sys.exit()
      if args.value:
         results = sip_client.get('indicators?value={}'.format(args.value))
         #print(results)
         #print(type(results))
         for x in results:
            if args.details:
               print(sip_client.get('indicators/{}'.format(x["id"])))
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
      if args.status:
         print("updating status of {} to {}".format(args.id,args.status))
         data = { 'status' : args.status }
         results = sip_client.put('/api/indicators/{}'.format(args.id),data)
         print(results)

 

   if args.command == 'create':
      user = config['sip']['user']

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

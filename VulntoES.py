#!/usr/bin/env python

from datetime import datetime
from elasticsearch import Elasticsearch
import json
import time
import codecs
import struct
import locale
import glob
import sys
import getopt
import xml.etree.ElementTree as xml
import re
#import socket
#import pprint



class NessusES:
	"This clas will parse an Nessus v2 XML file and create an object"
	
	def __init__(self, input_file,es_ip):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.es = Elasticsearch([{'host':es_ip}])
		
		
	def displayInputFileName(self):
		print self.input_file
		
	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)
		
	def toES(self):
		"Returns a dict of dictionaries for each issue in the report"
		#Nessus root node only has 2 children. policy and report, we grab report here
		report = self.root.getchildren()[1]
		dict_item={}
		#each child node of report is a report host - rh
		for rh in report:		
			ip = rh.attrib['name']
			host_item={}	
			#print rh.tag
			#iterate through attributes of ReportHost tags
			for tag in rh.getchildren():
				dict_item={}
				if tag.tag == 'HostProperties':
					for child in tag.getchildren():
						if child.attrib['name'] == 'HOST_END':
							host_item['time'] = child.text
						if child.attrib['name'] == 'operating-system':
							host_item['operating-system'] = child.text
						if child.attrib['name'] == 'mac-address':
							host_item['mac-address'] = child.text
						if child.attrib['name'] == 'host-fqdn':
							host_item['fqdn'] = child.text
						host_item['ip'] = ip
				elif tag.tag == 'ReportItem':
					if tag.attrib['port']:
						dict_item['port'] = tag.attrib['port']
					if tag.attrib['svc_name']:
						dict_item['svc_name'] = tag.attrib['svc_name']
					if tag.attrib['protocol']:
						dict_item['protocol'] = tag.attrib['protocol']
					if tag.attrib['severity']:
						dict_item['severity'] = tag.attrib['severity']
					if tag.attrib['pluginID']:
						dict_item['pluginID'] = tag.attrib['pluginID']
					if tag.attrib['pluginName']:
						dict_item['pluginName'] = tag.attrib['pluginName']
					if tag.attrib['pluginFamily']:
						dict_item['pluginFamily'] = tag.attrib['pluginFamily']
					#Iterate through child tags and texts of ReportItems
					#These are necessary because there can be multiple of these tags
					dict_item['cve'] = []
					dict_item['bid'] = []
					dict_item['xref'] = []
					for child in tag.getchildren():
						#print child.tag
						if child.tag == 'solution':
							dict_item[child.tag] = child.text
						if child.tag == 'risk_factor':
							dict_item[child.tag] = child.text
						if child.tag == 'description':
							dict_item[child.tag] = child.text
						if child.tag == 'synopsis':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_output':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_version':
							dict_item[child.tag] = child.text
						if child.tag == 'see_also':
							dict_item[child.tag] = child.text
						if child.tag == 'xref':
							dict_item[child.tag].append(child.text)
						if child.tag == 'bid':
							dict_item[child.tag].append(child.text)
						if child.tag == 'cve':
							dict_item[child.tag].append(child.text)
						if child.tag == 'cvss_base_score':
							dict_item[child.tag] = float(child.text)
						if child.tag == 'cvss_temporal_score':
							dict_item[child.tag] = float(child.text)
						if child.tag == 'cvss_vector':
							dict_item[child.tag] = child.text
						if child.tag == 'exploit_available':
							if child.text == 'true':
								dict_item[child.tag] = 1
							else:
								dict_item[child.tag] = 0
						if child.tag == 'plugin_modification_date':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_type':
							dict_item[child.tag] = child.text
				self.es.index(index="vulns",doc_type="vuln", body=json.dumps(dict(host_item.items()+dict_item.items())))	



def usage():
		print "Usage: VulntoES.py [-i input_file | input_file=input_file] [-e elasticsearch_ip | es_ip=es_ip_address] [-r report_type | --report_type=type] [-h | --help]"
def main():

	letters = 'i:e:r:h' #input_file, es_ip_address, report_type, create_sql, create_xml, help
	keywords = ['input-file=', 'es_ip=','report_type=', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = ''
	es_ip = ''
	report_type = ''
	
	for o,p in opts:
	  if o in ['-i','--input-file=']:
		in_file = p
	  elif o in ['-r', '--report_type=']:
	  	report_type = p
	  elif o in ['-e', '--es_ip=']:
	  	es_ip=p
	  elif o in ['-h', '--help']:
		 usage()
		 sys.exit()

	
	if (len(sys.argv) < 1):
		usage()
		sys.exit()
	
	try:
		with open(in_file) as f: pass
	except IOError as e:
		print "Input file does not exist. Exiting."
		sys.exit()
	
	if report_type.lower() == 'nessus':
		print "Sending Nessus data to Elasticsearch"
		np = NessusES(in_file,es_ip)
		np.toES()
#	elif report_type.lower() == 'nikto':
#		np = NiktoParser(in_file)
#		syslogger = Niktologger(np,es_ip)
#	elif report_type.lower() == 'nmap':
#		np = NmapParser(in_file)
#		syslogger = Nmaplogger(np,es_ip)
	else:
		print "Error: Invalid report type specified. Available options: nessus, nikto, nmap"
		sys.exit()

if __name__ == "__main__":
	main()

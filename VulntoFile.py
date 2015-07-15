#!/usr/bin/env python

from datetime import datetime
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
	"This class will parse an Nessus v2 XML file and send it to Elasticsearch"

	def __init__(self, input_file,output_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.output_file = output_file


	def displayInputFileName(self):
		print self.input_file

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toFile(self):
		"Returns a dict of dictionaries for each issue in the report"
		#Nessus root node only has 2 children. policy and report, we grab report here
		report = self.root.getchildren()[1]
		dict_item={}
		#each child node of report is a report host - rh
		with open(self.output_file + ".txt", "a") as outfile:
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
								print host_item['time']
								host_item['time'] = datetime.strptime(host_item['time'], '%a %b %d %H:%M:%S %Y')
								host_item['time'] = datetime.strftime(host_item['time'], '%Y-%m-%dT%H:%M:%S.000Z')
							if child.attrib['name'] == 'operating-system':
								host_item['operating-system'] = child.text
							if child.attrib['name'] == 'mac-address':
								host_item['mac-address'] = child.text
							if child.attrib['name'] == 'host-fqdn':
								host_item['fqdn'] = child.text
							host_item['ip'] = ip
					elif tag.tag == 'ReportItem':
						dict_item['scanner'] = 'nessus'
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

					#self.es.index(index=self.index_name,doc_type="vuln", body=json.dumps(dict(host_item.items()+dict_item.items())))
					outfile.write(json.dumps(dict(host_item.items()+dict_item.items()), sort_keys=True))
					outfile.write("\n")


class NmapES:
	"This class will parse an Nmap XML file and send data to Elasticsearch"

	def __init__(self, input_file,output_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.output_file = output_file

	def displayInputFileName(self):
		print self.input_file

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toFile(self):
		"Returns a list of dictionaries (only for open ports) for each host in the report"
		for h in self.root.iter('host'):
			dict_item = {}
			dict_item['scanner'] = 'nmap'
			for c in h:
				if c.tag == 'address':
					if c.attrib['addr']:
						dict_item['ip'] = c.attrib['addr']
				elif c.tag == 'hostnames':
					for names in c.getchildren():
						if names.attrib['name']:
							dict_item['hostname'] = names.attrib['name']
				elif c.tag == 'ports':
					for port in c.getchildren():
						dict_itemb = {}
						if port.tag == 'port':
							dict_item['port'] = port.attrib['portid']
							dict_item['protocol'] = port.attrib['protocol']
							for p in port.getchildren():
								if p.tag == 'state':
									dict_item['state'] = p.attrib['state']
								elif p.tag == 'service':
									dict_item['service'] = p.attrib['name']
							if dict_item['state'] == 'open':
								#Only sends document to ES if the port is open
								self.es.index(index=self.output_file,doc_type="vuln", body=json.dumps(dict_item))

class NiktoFile:
	"This class will parse an Nikto XML file and create an object"

	def __init__(self, input_file,output_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.output_file = output_file

	def displayInputFileName(self):
		print self.input_file

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toFile(self):
		"Sends each item to Elasticsearch as a unique document"
		for item in self.root.iter('item'):
			dict_item = {}
			dict_item['scanner'] = 'nikto'
			dict_item['osvdbid'] = item.attrib['osvdbid']
			dict_item['method'] =  item.attrib['method']
			for c in item:
				if c.tag == 'description':
					dict_item['description'] = c.text
				elif c.tag == 'uri':
					dict_item['uri'] = c.text
				elif c.tag == 'namelink':
					#regex = re.compile(":\/\/([\w]*):")
					regex = re.compile("(https?)://([.0-9a-zA-Z-]+)(/?.*?)([^/]*)")
					#print regex.search(c.text).groups()
					dict_item['hostname'] = regex.search(c.text).groups()[1]
					dict_item['srcport'] = regex.search(c.text).groups()[3][1:]
					dict_item['site'] = regex.search(c.text).groups()[0] + '://' +  regex.search(c.text).groups()[1]
				elif c.tag == 'iplink':
					regex = re.compile("((?:[0-9]{1,3}\.){3}[0-9]{1,3})")
					dict_item['srcip'] = regex.search(c.text).groups()[0]
			self.es.index(index=self.output_file,doc_type="vuln", body=json.dumps(dict_item))


class OpenVasES:
	"This class will parse an OpenVAS XML file and send it to Elasticsearch"

	def __init__(self, input_file,output_file):
		self.input_file = input_file
                self.displayInputFileName()
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.issueList = self.__createIssuesList()
		self.portList = self.__createPortsList()
		self.output_file = output_file

	def displayInputFileName(self):
		print self.input_file

	def __importXML(self):
		#Parse XML directly from the file path
                self.displayInputFileName()
		return xml.parse(self.input_file)
                self.displayInputFileName()

	def __createIssuesList(self):
		"Returns a list of dictionaries for each issue in the report"
		issuesList = [];
		for result in self.root.iter('result'):
			issueDict = {};
			issueDict['scanner'] = 'openvas'
			if result.find('host') is not None:
				issueDict['ip'] = unicode(result.find('host').text)
				#print issueDict['host']
			for nvt in result.iter('nvt'):
				issueDict['oid'] = unicode(nvt.attrib['oid'])
				for child in nvt:
					issueDict[child.tag] = unicode(child.text)

			if result.find('description') is not None:
				issueDict['description'] = unicode(result.find('description').text)
			if result.find('port') is not None:
				issueDict['port'] = unicode(result.find('port').text)
			if result.find('threat') is not None:
				issueDict['threat'] = unicode(result.find('threat').text)
			if result.find('severity') is not None:
				issueDict['severity'] = unicode(result.find('severity').text)
			if result.find('scan_nvt_version') is not None:
                            issueDict['scan_nvt_version'] = unicode(result.find('scan_nvt_version').text)
			if issueDict:
				issuesList.append(issueDict)

		#for x in issuesList:
		#	print x['description']
		return issuesList



	def __createPortsList(self):
		"Returns a list of dictionaries for each ports in the report"
		portsList = [];
		for p in self.root.iter('ports'):
			for port in p:
				portDict = {};
				portDict['scanner'] = 'openvas'
				if port.text != 'general/tcp':
					d = self.parsePort(port.text)
					#print d['service']
					if port.find('host').text is not None: portDict['ip'] = port.find('host').text
					if d != None:
						portDict['service'] = d['service']
						portDict['port'] = d['port']
						portDict['protocol'] = d['protocol']
						portsList.append(portDict)



		return portsList

	def parsePort(self,string):
		fieldsDict={};
		portsParsed = re.search(r'(\S*\b)\s\((\d+)\/(\w+)',string)
		#portsParsed = re.search('(\S*)\s\((\d+)\/(\w+)',string)
		#print string
		if portsParsed:
			fieldsDict['service'] = unicode(portsParsed.group(1))
			fieldsDict['port'] = unicode(portsParsed.group(2))
			fieldsDict['protocol'] = unicode(portsParsed.group(3))
			#print fieldsDict
			return fieldsDict
		return None


	def toFile(self):
		for item in self.issueList:
			self.es.index(index=self.output_file,doc_type="vuln", body=json.dumps(item))
		for port in self.portList:
			self.es.index(index=self.output_file,doc_type="vuln", body=json.dumps(port))


def usage():
		print "Usage: VulntoFile.py [-i input_file | input_file=input_file] [-o output_file] [-r report_type | --report_type=type] [-h | --help]"
def main():

	letters = 'i:o:r:h' #input_file, output_file, report_type, create_sql, create_xml, help
	keywords = ['input-file=', 'output_file=', 'report_type=', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = ''
	report_type = ''
	output_file = ''

	for o,p in opts:
	  if o in ['-i','--input-file=']:
		in_file = p
	  elif o in ['-r', '--report_type=']:
	  	report_type = p
	  elif o in ['-o', '--output_file=']:
		output_file=p
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
		np = NessusES(in_file,output_file)
		np.toFile()
	elif report_type.lower() == 'nikto':
		print "Sending Nikto data to Elasticsearch"
		np = NiktoFile(in_file,output_file)
		np.toFile()
	elif report_type.lower() == 'nmap':
		print "Sending Nmap data to Elasticsearch"
		np = NmapES(in_file,output_file)
		np.toFile()
	elif report_type.lower() == 'openvas':
		np = OpenVasES(in_file,output_file)
		np.toFile()
	else:
		print "Error: Invalid report type specified. Available options: nessus, nikto, nmap, openvas"
		sys.exit()

if __name__ == "__main__":
	main()
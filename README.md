VulntoES
========

Vulnerability Data in ES

This small python script will ingest several different types of vulnerability/port scanners and import that data into Elasticsearch. Right now it supports:
 - Nessus
 - Nikto
 - Nmap
 - Openvas 

The script creates a python dict from a vulnerability scanner output. It converts that to JSON and inserts that document into Elasticsearch. 

"Usage: VulntoES.py [-i input_file | input_file=input_file] [-e elasticsearch_ip | es_ip=es_ip_address] [-r report_type | --report_type=type] [-h | --help]"

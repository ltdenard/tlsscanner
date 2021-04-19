# -*- coding: utf-8 -*-
import os
import sys
import boto3
import logging
import logging.handlers
from time import time, sleep
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from wafw00f.main import WAFW00F
import json
import ast
import multiprocessing
import OpenSSL
import itertools
import uuid
import subprocess
from queue import Queue
from threading import Thread
import eventlet
import xmltodict
import validators
import signal

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

AWS_SERVER_PUBLIC_KEY = os.environ['AWS_SERVER_PUBLIC_KEY']
AWS_SERVER_SECRET_KEY = os.environ['AWS_SERVER_SECRET_KEY']
REGION_NAME = os.environ['REGION_NAME']
BUCKET_NAME = os.environ['BUCKET_NAME']

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_SERVER_PUBLIC_KEY,
    aws_secret_access_key=AWS_SERVER_SECRET_KEY,
    region_name=REGION_NAME
)


class TLSScan():
    def __init__(self, _scan_uuid, domain, port_list=[80,443]):
        self._domain = domain
        self._port_list = port_list
        self._sslscan = os.getcwd() + "/sslscan"
        self._scan_uuid = _scan_uuid
        self._base_dir = '/tmp/'
        self._logging_folder = self._base_dir + 'logs/'
        if not os.path.exists(self._logging_folder):
            os.makedirs(self._logging_folder)
        self._log_filename = self._scan_uuid + '.log'
        self._logging_filename = self._logging_folder + self._log_filename
        self._num_worker_threads = 4
        self._results_list = []
        self._crawled_headers = []
        self._logger = logging.getLogger(self._scan_uuid)
        self._logger.setLevel(logging.INFO)
        _formatter = logging.Formatter(
            '%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s')
        _filehand = logging.handlers.RotatingFileHandler(
        self._logging_filename, mode='a', maxBytes=1000000, backupCount=5)
        _filehand.setFormatter(_formatter)
        self._logger.addHandler(_filehand)

    def exec_command(self, cmd):
        subprocess.call(cmd, shell=True)
        return

    def get_redir_link(self, link, links=[], counter=0):
        self._logger.info('Crawling {}...'.format(link))
        links.append(link)
        response = None
        if counter == 10:
            return links
        try:
            response = requests.get(
                link,
                allow_redirects=False,
                verify=False,
                timeout=10)
        except requests.exceptions.SSLError:
            links.append('SSL bad handshake/client cert error')
        except OpenSSL.SSL.SysCallError:
            links.append('OpenSSLSysCallError')
        except requests.exceptions.ConnectionError:
            links.append('ConnectionError')
        except requests.exceptions.ReadTimeout:
            links.append('ReadTimeout')
        if response is not None:
            if 'Location' in response.headers.keys():
                counter = counter +1
                if 'http' not in response.headers['Location']:
                    basedomain = link + response.headers['Location']
                    self.get_redir_link(
                        basedomain,
                        links,
                        counter)
                else:
                    self.get_redir_link(
                        response.headers['Location'],
                        links,
                        counter)
            self._crawled_headers.append({link:dict(response.headers)})
        return links


    def trim_results(self, end_results):
        self._logger.info('cleaning up dictionary results...')
        dict_results = {}
        for l in end_results:
            if len(l) > 1:
                k = l[-1]
                tmp = l.pop(-1)
                v = l
                if k not in dict_results.keys():
                    dict_results.update({ k: v })
                else:
                    dict_results[k].extend(v)
            else:
                if l[0] not in dict_results.keys():
                    dict_results.update({ l[0]:[] })
                else:
                    pass
        return dict_results


    def run_link_crawl(self):
        while True:
            link = self.cl_q.get()
            try:
                with eventlet.timeout.Timeout(10, False):
                    links_dict = self.get_redir_link(link, links=[], counter=0)
            except:
                links_dict = [link, 'ReadTimeout']
            self.cl_q.task_done()
            self._results_list.append(links_dict)


    def crawl_links(self, domain_list, port_list):
        domain_port_list = list(itertools.chain.from_iterable([['{}:{}'.format(domain,port) for port in port_list] for domain in domain_list]))
        domain_port_proto_list = list(itertools.chain.from_iterable([['{}://{}'.format(proto,domain) for proto in ['http','https']] for domain in domain_port_list]))
        self.cl_q = Queue()
        for _ in range(self._num_worker_threads):
            t = Thread(target=self.run_link_crawl)
            t.daemon = True
            t.start()
        for item in domain_port_proto_list:
            self.cl_q.put(item)
        self.cl_q.join()
        return self.trim_results(self._results_list)


    def domains_to_scan(self, redir_results):
        self._logger.info('figuring out domains to scan...')
        scan_domain = []
        domain_list = [k.split('/')[2] for k in redir_results.keys() if 'http' in k]
        for domain in domain_list:
            self._logger.info('processing: {}'.format(domain))
            if ':' in domain:
                domain = domain.split(':')[0]
            scan_domain.append(domain)
        return list(set(scan_domain))


    def redir_to_domain(self, redir_results):
        self._logger.info('grouping link crawled results...')
        tmp_dict = {}
        for k in redir_results.keys():
            self._logger.info('processing: {}'.format(k))
            values = redir_results[k]
            if 'http' in k:
                key = k.split('/')[2]
                if ':' in key:
                    key = key.split(':')[0]
                if key not in tmp_dict:
                    tmp_dict.update({key: values})
                else:
                    tmp_dict[key].extend(values)
                    tmp_values = tmp_dict.get(key)
                    if tmp_values:
                        tmp_dict[key] = list(set(tmp_values))
                    tmp_values = None
        return tmp_dict

    def no_ssl_check(self, domain):
        census = []
        try:
            nonssl_test = requests.get(
                    'http://{}'.format(domain),
                    allow_redirects=False,
                    verify=False,
                    timeout=10
                )
            if nonssl_test.status_code == 200:
                census.append(True)
        except requests.exceptions.SSLError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.ReadTimeout:
            pass
        except OpenSSL.SSL.SysCallError:
            pass
        if True in census:
            return domain
        else:
            return []


    def run_ssl_check(self):
        while True:
            domain = self.nossl_q.get()
            no_ssl_results = self.no_ssl_check(domain)
            self.nossl_q.task_done()
            if no_ssl_results:
                self.nossl_results.append(no_ssl_results)

    def bulk_no_ssl_check(self, domains, ports):
        domain_list = []
        for port in ports:
            for domain in domains:
                domain_list.append('{}:{}'.format(domain,str(port)))
        self.nossl_results = []
        self.nossl_q = Queue()
        for _ in range(self._num_worker_threads):
            t = Thread(target=self.run_ssl_check)
            t.daemon = True
            t.start()
        for item in domain_list:
            self.nossl_q.put(item)
        self.nossl_q.join()
        return self.nossl_results


    def create_waf_list(self, domains, ports):
        return_list = []
        for domain in domains:
            for port in ports:
                return_list.append("http://{}:{}".format(domain,port))
        return return_list

    def cleanup_waf(self, waf_list):
        waf_dict = {}
        for d in waf_list:
            for dd,kk in d.items():
                if dd not in waf_dict.keys():
                    waf_dict.update({dd: kk})
                else:
                    waf_dict[dd].extend(kk)
        waf_clean_dict = {}
        for k,v in waf_dict.items():
            waf_clean_dict.update({k:list(set(v))})
        return waf_clean_dict

    def waf_check(self, domain):
        waf_detect = WAFW00F(target=domain)
        waf_status = waf_detect.identwaf(findall=False)
        return {domain:waf_status}

    def waf_run(self, scanable_domains):
        waf_results = []
        waf_results_list = []
        waf_final_results = []

        def signal_handler(signum, frame):
            self._logger.info('Timeout on WAF...')

        waf_list = self.create_waf_list(scanable_domains,self._port_list)
        for waf_item in waf_list:
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(30)
            try:
                self._logger.info('WAF scan for {}...'.format(waf_item))
                tmp_result = self.waf_check(waf_item)
                waf_results.append(tmp_result)
            except:
                signal.alarm(0)
                break
            signal.alarm(0)
        for item in waf_results:
            if item:
                waf_results_list.append(item)
        if waf_results_list:
            waf_final_results = self.cleanup_waf(waf_results_list)
        return waf_final_results

    def convert_xml_to_json(self, input_file):
        try:
            with open(input_file, 'r') as f:
                xml_data = f.read().strip()
                json_data = xmltodict.parse(xml_data)
                return json_data
        except Exception as e:
            print(e)
            return {}


    def run_tlsscan(self, scanable_domains):
        scan_list = ['{}:{}'.format(d,p) for p in self._port_list for d in scanable_domains]
        self._logger.info('Starting SSL/TLS scanning...')
        run_list = []
        file_list = []
        for d in scan_list:
            self._logger.info(d)
            input_file_name = "{}{}.xml".format(self._logging_folder, d)
            tmp_cmd = "{} --xml={} {}".format(self._sslscan, input_file_name, d)
            run_list.append(tmp_cmd)
            file_list.append(input_file_name)

        scan_result_list = []
        for cmd in run_list:
            self.exec_command(cmd)
        for scan_in in file_list:
            scan_result = self.convert_xml_to_json(scan_in)
            if scan_result:
                scan_result_list.append(scan_result)
            os.remove(scan_in)
        return scan_result_list

    def scan_domains(self):
        self._logger.info('Startings scan...')
        return_dict = {}
        crawl_results = []
        scanable_domains = []
        domain_aliases = []
        self._logger.info('Startings link crawl...')
        crawl_results = self.crawl_links([self._domain], self._port_list)
        return_dict.update({"crawled_links":crawl_results})

        self._logger.info('Startings link crawl header collection...')
        return_dict.update({"crawled_headers":self._crawled_headers})

        self._logger.info('checking which links are TLS scannable...')
        scanable_domains = self.domains_to_scan(crawl_results)
        return_dict.update({"scannable_domains":scanable_domains})

        self._logger.info('checking which domains are cnames...')
        domain_aliases = self.redir_to_domain(crawl_results)
        return_dict.update({"alias_domains":domain_aliases})

        self._logger.info('checking which links have no ssl...')
        no_ssl_domains = self.bulk_no_ssl_check(scanable_domains, self._port_list)
        return_dict.update({"no_ssl":no_ssl_domains})

        self._logger.info('starting sslscan...')
        scan_result_list = self.run_tlsscan(scanable_domains)
        return_dict.update({"scan_result":scan_result_list})

        self._logger.info('starting wafw00f...')
        # TODO: figure out how to keep this from failing
        # on sites that are slow.
        # waf_final_results = self.waf_run(scanable_domains)
        waf_final_results = []
        return_dict.update({"waf_results":waf_final_results})

        self._logger.info('writing json file with results...')
        final_filename = "{}.json".format(self._scan_uuid)
        final_json_file = "/tmp/{}".format(final_filename)
        with open(final_json_file, "w") as f:
            json.dump(return_dict, f, indent=4)

        self._logger.info('writing log file to S3...')
        s3_client.upload_file(self._logging_filename, BUCKET_NAME, self._log_filename)
        self._logger.info('writing json results file to S3...')
        s3_client.upload_file(final_json_file, BUCKET_NAME, final_filename)

        self._logger.info('finished')



def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def is_valid_port(port_numbers):
    return_status = []
    for port_number in port_numbers:
        try:
            port = int(port_number)
            if 0 < port < 65536:
                return_status.append(True)
            else:
                return_status.append(False)
        except Exception as e:
            print(e)
            pass
            return_status.append(False)
    if False not in return_status:
        return True
    return False



def lambda_handler(event, context):
    try:
        domain_name = event.get("domain")
        port_numbers = event.get("port", [80, 443])
        uuid_number = event.get("uuid")
        if validators.domain(domain_name) and is_valid_port(port_numbers) and is_valid_uuid(uuid_number):
            obj = TLSScan(uuid_number, domain_name, port_numbers)
            obj.scan_domains()
            return True
    except Exception as e:
        print(e)
        pass
    return False

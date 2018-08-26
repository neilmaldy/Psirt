import requests
from bs4 import BeautifulSoup
import os
import json
import logging
import time
import sys
import datetime
import pickle

debug_it = 1
output_file = 'advisories_' + datetime.date.today().strftime("%Y%U%w")


def print_to_log(log_string):
    """ Print to log file (stderr)
    Prints the logString to stderr, prepends date and time
    """
    print(time.strftime("%H:%M:%S") + ": " + log_string, file=sys.stderr)
    logging.info(time.strftime("%H:%M:%S") + ": " + log_string)
    if debug_it:
        with open("temp.log", mode='a', encoding='utf-8') as templog:
            print(time.strftime("%H:%M:%S") + ": " + log_string, file=templog)


class ProductAdvisory:

    failed_attributes = []

    def __init__(self, product_name, advisory):
        self.product = product_name
        self.ntap_advisory_id = advisory['ntap_advisory_id']
        self.title = advisory['kb_title']
        self.summary = advisory['kb_summary']
        self.cves = set()
        for cve in advisory['kb_scoring_calc']:
            self.cves.add(cve + ' ' + advisory['kb_scoring_calc'][cve]['score']
                          + ' ' + advisory['kb_scoring_calc'][cve]['range'])
        self.fixes = set()
        for fix in advisory['kb_fixes']:
            if fix['product'] == product:
                if 'fixes' in fix:
                    for fix_link in fix['fixes']:
                        if 'link' in fix_link:
                            self.fixes.add(fix_link['link'])
                        else:
                            if fix['wontfix'] == 'true':
                                self.fixes.add('WONT_FIX')
                            else:
                                self.fixes.add('')

    def list_changes(self, other):
        changes_list = []
        attributes_to_ignore = ['ib_row', 'raw_tb']
        for k, v in vars(self).items():
            try:
                if k not in attributes_to_ignore and other.__getattribute__(k) != v:
                    try:
                        if v.date() != other.__getattribute__(k).date():
                            changes_list.append((k, v, other.__getattribute__(k)))
                    except (AttributeError, ValueError):
                        if other.__getattribute__(k) != v:
                            changes_list.append((k, v, other.__getattribute__(k)))
            except AttributeError:
                if k not in ProductAdvisory.failed_attributes:
                    ProductAdvisory.failed_attributes.append(k)
                    print_to_log("Problem comparing " + k + " to previous, possibly a new column added to the report")

        return changes_list


root_url = 'https://security.netapp.com/data/advisory/'
response = requests.get(root_url)
data = response.text
soup = BeautifulSoup(data, 'lxml')

if False:
    for link in soup.find_all('a'):
        if link.get('href').endswith('.json'):
            print(link.get('href'))
            adv = requests.get(root_url + link.get('href'))
            open(link.get('href'), 'wb').write(adv.content)

advisories = []
for f in os.listdir('.'):
    if f.endswith('.json'):
        with open(f, 'r') as fp:
            advisories.append(json.loads(fp.read()))

advisory_table = {}
for adv in advisories:
    for product in adv['kb_affected_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, adv)

with open(output_file + '.pickle', 'wb') as f:
    pickle.dump(advisory_table, f)

days = 1

while days < 90:
    day = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%Y%U%w")
    if not os.path.isfile('advisories_' + day + '.pickle'):
        days += 1
        print_to_log("Comparing to history from " + day)
        continue
    else:
        print_to_log("Comparing to history from " + day)
        previous_advisories = {}
        with open('advisories_' + day + '.pickle', 'rb') as f:
            previous_advisories = pickle.load(f)
        break

for key, product_advisory in advisory_table.items():
    print(product_advisory.ntap_advisory_id + ':' + product_advisory.product)


print('Done.')
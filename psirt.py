import requests
from bs4 import BeautifulSoup
import os
import json
import logging
import time
import sys
import datetime
import pickle
import xlsxwriter

debug_it = 1
output_file = 'advisories_' + time.strftime("%Y%m%d")
# time.strftime("%Y%m%d%H%M%S")

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

    def __init__(self, product_name, product_status, advisory):
        self.product = product_name
        self.product_status = product_status
        self.changes = set()
        self.ntap_advisory_id = advisory['ntap_advisory_id']
        self.title = advisory['kb_title']
        self.summary = advisory['kb_summary']

        self.cves_set = set()
        for cve in advisory['kb_scoring_calc']:
            self.cves_set.add(cve + ' ' + advisory['kb_scoring_calc'][cve]['score']
                          + ' ' + advisory['kb_scoring_calc'][cve]['range'])
        self.cves = ''
        for cve in self.cves_set:
            self.cves += cve + '\n'

        self.fixes_set = set()
        for fix in advisory['kb_fixes']:
            if fix['product'] == product:
                if 'fixes' in fix:
                    for fix_link in fix['fixes']:
                        if 'link' in fix_link:
                            self.fixes_set.add(fix_link['link'])
                        else:
                            if fix['wontfix'] == 'true':
                                self.fixes_set.add('WONT_FIX')
                            else:
                                self.fixes_set.add('')

    def list_changes(self, other):
        changes_list = []
        attributes_to_ignore = ['ib_row', 'raw_tb']
        for k, v in vars(self).items():
            try:
                if k not in attributes_to_ignore and other.__getattribute__(k) != v:
                    try:
                        if v.date() != other.__getattribute__(k).date():
                            changes_list.append((k, v, other.__getattribute__(k)))
                            self.changes.add(k)
                    except (AttributeError, ValueError):
                        if other.__getattribute__(k) != v:
                            changes_list.append((k, v, other.__getattribute__(k)))
                            self.changes.add(k)
            except AttributeError:
                if k not in ProductAdvisory.failed_attributes:
                    ProductAdvisory.failed_attributes.append(k)
                    print_to_log("Problem comparing '" + k + "' to previous, possibly a new column added to the report")

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
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Affected', adv)
    for product in adv['kb_investigating_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Investigating', adv)
    for product in adv['kb_unaffected_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Unaffected', adv)

with open(output_file + '.pickle', 'wb') as f:
    pickle.dump(advisory_table, f)

days = 1
previous_advisories = None
while days < 90:
    day = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%Y%m%d")
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

if previous_advisories:
    new_advisories = set(advisory_table.keys()) - set(previous_advisories.keys())
    for key in new_advisories:
        print('New advisory: ' + key)
    for key, product_advisory  in advisory_table.items():
        if key in previous_advisories:
            for change in product_advisory.list_changes(previous_advisories[key]):
                print(change)

for key, product_advisory in advisory_table.items():
    print(product_advisory.ntap_advisory_id + ':' + product_advisory.product)

column_list = [('Advisory ID', 'ntap_advisory_id', 25),
               ('Title', 'title', 40),
               ('Product', 'product', 30),
               ('CVEs', 'cves', 30)]

workbook = xlsxwriter.Workbook(output_file + '.xlsx')
worksheet = workbook.add_worksheet()
fill_yellow_format = workbook.add_format({'bg_color': 'yellow', 'text_wrap': True, 'border': 1})
wrap_format = workbook.add_format({'text_wrap': True})
heading_format = workbook.add_format({'font_color': 'white', 'bg_color': 'blue', 'bold': True, 'border': 1, 'align': 'center'})
data_cell_format = workbook.add_format({'text_wrap': True, 'border': 1})

row = 0
col = 0

for column_heading, attribute_name, column_width in column_list:
    worksheet.set_column(first_col=col, last_col=0, width=column_width, cell_format=wrap_format)
    worksheet.write(row, col, column_heading, heading_format)
    col += 1

row = 1
col = 0
for key in advisory_table:
    for column_heading, attribute_name, column_width in column_list:
        if attribute_name == 'ntap_advisory_id':
            worksheet.write_url(row, col, 'https://security.netapp.com/advisory/' + advisory_table[key].__getattribute__(attribute_name).lower(), string=advisory_table[key].__getattribute__(attribute_name), cell_format=data_cell_format)
        elif attribute_name in advisory_table[key].changes:
            worksheet.write(row, col, advisory_table[key].__getattribute__(attribute_name), fill_yellow_format)
        else:
            worksheet.write(row, col, advisory_table[key].__getattribute__(attribute_name), data_cell_format)
        col += 1
    row += 1
    col = 0

worksheet.autofilter(0, 0, len(advisory_table), len(column_list)-1)

workbook.close()

print('Done.')

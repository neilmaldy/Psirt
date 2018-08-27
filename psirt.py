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

debug_it = 0
output_file = 'advisories_' + time.strftime("%Y%m%d")
# time.strftime("%Y%m%d%H%M%S")
output_dir = 'AdvisoryDir'
if not os.path.isdir(output_dir):
    os.makedirs(output_dir)


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
        self.first_fixed = ''
        self.notes = ''
        self.impact = advisory['kb_impact']
        self.version = advisory['kb_rev_history'][-1]['version']
        self.comment = advisory['kb_rev_history'][-1]['comment']
        self.date = advisory['kb_rev_history'][-1]['date']
        self.workarounds = advisory['kb_workarounds']
        self.cves_set = []
        for cve in advisory['kb_scoring_calc']:
            self.cves_set.append(cve + ' ' + advisory['kb_scoring_calc'][cve]['score']
                          + ' ' + advisory['kb_scoring_calc'][cve]['range'])
        self.cves = ''
        for cve in self.cves_set:
            self.cves += cve + '\n'

        self.fixes_set = []
        for fix in advisory['kb_fixes']:
            if fix['product'] == product:
                if 'fixes' in fix:
                    for fix_link in fix['fixes']:
                        if 'link' in fix_link:
                            self.fixes_set.append(fix_link['link'])
                        else:
                            if fix['wontfix'] == 'true':
                                self.fixes_set.append('WONT_FIX')
                            else:
                                self.fixes_set.append('')
        self.fixes = ''
        for fix in self.fixes_set:
            self.fixes += fix + '\n'

    def list_changes(self, other):
        changes_list = []
        attributes_to_ignore = ['ntap_advisory_id', 'raw_tb', 'cves_set', 'fixes_set', 'changes', 'product_name']
        for k, v in vars(self).items():
            try:
                if k not in attributes_to_ignore and other.__getattribute__(k) != v:
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
            if debug_it or True:
                print_to_log(link.get('href'))
            adv = requests.get(root_url + link.get('href'))
            open(os.path.join(output_dir, link.get('href')), 'wb').write(adv.content)

advisories = []
for f in os.listdir(output_dir):
    if f.endswith('.json'):
        with open(os.path.join(output_dir,f), 'r') as fp:
            advisories.append(json.loads(fp.read()))

advisory_table = {}
for adv in advisories:
    for product in adv['kb_affected_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Affected', adv)
    for product in adv['kb_investigating_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Investigating', adv)
    # for product in adv['kb_unaffected_list']:
    #     advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Unaffected', adv)

with open(output_file + '.pickle', 'wb') as f:
    pickle.dump(advisory_table, f)

days = 1
previous_advisories = None
while days < 90:
    day = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%Y%m%d")
    if not os.path.isfile('advisories_' + day + '.pickle'):
        days += 1
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
        if debug_it or True:
            print_to_log('New advisory: ' + key)
        advisory_table[key].changes.add('product')
    for key, product_advisory  in advisory_table.items():
        if key in previous_advisories:
            for change in product_advisory.list_changes(previous_advisories[key]):
                if debug_it or True:
                    print_to_log(key + str(change))

column_list = [('Advisory ID', 'ntap_advisory_id', 20),
               ('Title', 'title', 50),
               ('Product', 'product', 17),
               ('Status', 'product_status', 17),
               ('CVEs', 'cves', 22),
               ('Description', 'summary', 48),
               ('Fix Links', 'fixes', 62),
               ('First Fixed in Release', 'first_fixed', 13),
               ('Notes', 'notes', 26)
               ]

workbook = xlsxwriter.Workbook(output_file + '.xlsx')
worksheet = workbook.add_worksheet()
fill_yellow_format = workbook.add_format({'bg_color': 'yellow', 'text_wrap': True, 'border': 1, 'font_size': 8})
wrap_format = workbook.add_format({'text_wrap': True})
heading_format = workbook.add_format({'font_color': 'white', 'bg_color': 'blue', 'bold': True, 'border': 1, 'align': 'center', 'text_wrap': True})
data_cell_format = workbook.add_format({'text_wrap': True, 'border': 1, 'font_size': 8})

row = 0
col = 0

for column_heading, attribute_name, column_width in column_list:
    worksheet.set_column(first_col=col, last_col=col, width=column_width)
    worksheet.write(row, col, column_heading, heading_format)
    col += 1

row = 1
col = 0
for key in advisory_table:
    for column_heading, attribute_name, column_width in column_list:
        if attribute_name == 'ntap_advisory_id' and 'ntap_advisory_id' in advisory_table[key].changes:
            worksheet.write_url(row, col,
                                'https://security.netapp.com/advisory/' + advisory_table[key].__getattribute__(
                                    attribute_name).lower(),
                                string=advisory_table[key].__getattribute__(attribute_name),
                                cell_format=fill_yellow_format)
        elif attribute_name == 'ntap_advisory_id':
            worksheet.write_url(row, col, 'https://security.netapp.com/advisory/' + advisory_table[key].__getattribute__(attribute_name).lower(), string=advisory_table[key].__getattribute__(attribute_name), cell_format=data_cell_format)
        elif attribute_name in advisory_table[key].changes:
            worksheet.write_string(row, col, advisory_table[key].__getattribute__(attribute_name), fill_yellow_format)
        else:
            worksheet.write_string(row, col, advisory_table[key].__getattribute__(attribute_name), data_cell_format)
        col += 1
    row += 1
    col = 0

worksheet.autofilter(0, 0, len(advisory_table), len(column_list)-1)


workbook.close()

print('Done.')

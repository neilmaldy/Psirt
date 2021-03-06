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
import PySimpleGUI as sg
import platform

working_directory = None
download_advisories = False

while not working_directory:
    with sg.FlexForm('NetApp Security Advisories Summary v1.0') as form:
        form_rows = [[sg.Text('Choose working directory(required) and advisory.history file(optional)', size=(50, 1))],
                     [sg.Text('(The advisory.history file is used to check for changes)', size=(50, 1))],
                     [sg.Text('Working directory:', size=(14, 1)), sg.InputText(), sg.FolderBrowse()],
                     [sg.Text('History file:', size=(14, 1)), sg.InputText(default_text='None'), sg.FileBrowse()],
                     [sg.Checkbox('Download Advisories?', default=True)],
                     [sg.Submit(), sg.Cancel()]]

        button, values = form.LayoutAndShow(form_rows)

    if button is None or button == 'Cancel':
        sys.exit()

    working_directory, history_file, download_advisories = values

os.chdir(working_directory)

debug_it = 0
output_file = 'advisories_' + time.strftime("%Y%m%d")
# time.strftime("%Y%m%d%H%M%S")
output_dir = 'AdvisoryDir'
if not os.path.isdir(output_dir):
    os.makedirs(output_dir)
    download_advisories = True

logs = []

def print_to_log(log_string):
    """ Print to log file (stderr)
    Prints the logString to stderr, prepends date and time
    """
    global logs

    log = time.strftime("%H:%M:%S") + ": " + log_string
    print(log, file=sys.stderr)
    logging.info(log)
    logs.append(log)
    sg.EasyPrint(log, size=(180, 50))

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
        self.version = str(advisory['kb_rev_history'][-1]['version'])
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
        attributes_to_ignore = ['ntap_advisory_id', 'raw_tb', 'cves_set', 'fixes_set', 'changes', 'product_name', 'version', 'date', 'comment']
        for k, v in vars(self).items():
            try:
                if k not in attributes_to_ignore and other.__getattribute__(k) != v:
                    if other.__getattribute__(k) != v:
                        changes_list.append((k, v, other.__getattribute__(k)))
                        self.changes.add(k)
                        self.changes.add('ntap_advisory_id')
                        if self.version != other.version:
                            self.changes.add('version')
                        if self.date != other.date:
                            self.changes.add('date')
                        if self.comment != other.comment:
                            self.changes.add('comment')
            except AttributeError:
                if k not in ProductAdvisory.failed_attributes:
                    ProductAdvisory.failed_attributes.append(k)
                    print_to_log("Problem comparing '" + k + "' to previous, possibly a new column added to the report")

        return changes_list


root_url = 'https://security.netapp.com/data/advisory/'
response = requests.get(root_url)
data = response.text
soup = BeautifulSoup(data, 'lxml')

if download_advisories:
    for f in os.listdir(output_dir):
        if f.endswith('.json'):
            os.remove(os.path.join(output_dir, f))
    for link in soup.find_all('a'):
        if link.get('href').endswith('.json'):
            if debug_it or True:
                print_to_log('Downloading ' + link.get('href'))
            adv = requests.get(root_url + link.get('href'))
            open(os.path.join(output_dir, link.get('href')), 'wb').write(adv.content)

advisories = []
for f in os.listdir(output_dir):
    if f.endswith('.json'):
        with open(os.path.join(output_dir,f), 'r') as fp:
            advisories.append(json.loads(fp.read()))

advisory_table = {}
product_list = []
for adv in advisories:
    for product in adv['kb_affected_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Affected', adv)
        if product not in product_list:
            product_list.append(product)
    for product in adv['kb_investigating_list']:
        advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Investigating', adv)
        if product not in product_list:
            product_list.append(product)
    # for product in adv['kb_unaffected_list']:
    #    advisory_table[adv['ntap_advisory_id'] + ' ' + product] = ProductAdvisory(product, 'Unaffected', adv)
    #    if product not in product_list:
    #        product_list.append(product)

with open(output_file + '.history', 'wb') as f:
    pickle.dump(advisory_table, f)

with sg.FlexForm('NetApp Security Advisories Summary v1.0') as form:
    form_rows = [[sg.Text('Choose products to include in report, select one item and then CTRL-A to select all', size=(80, 1))],
                 [sg.Listbox(sorted(product_list), select_mode='multiple', size=(80, 40))],
                 [sg.Submit(), sg.Cancel()]]

    button, values = form.LayoutAndShow(form_rows)

if button is None or button == 'Cancel':
    sys.exit()

product_list = values[0]

previous_advisories = None
if history_file and history_file is not 'None' and os.path.isfile(history_file):
    with open(history_file, 'rb') as f:
        previous_advisories = pickle.load(f)

# days = 1
# while days < 90:
#     day = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%Y%m%d")
#     if not os.path.isfile('advisories_' + day + '.history'):
#         days += 1
#         continue
#     else:
#         print_to_log("Comparing to history from " + day)
#         previous_advisories = {}
#         with open('advisories_' + day + '.history', 'rb') as f:
#             previous_advisories = history.load(f)
#         break

if previous_advisories:
    new_advisories = set(advisory_table.keys()) - set(previous_advisories.keys())
    for key in new_advisories:
        if advisory_table[key].product in product_list:
            print_to_log('New advisory: ' + key)
            advisory_table[key].changes.add('ntap_advisory_id')
            advisory_table[key].changes.add('product')
    for key, product_advisory  in advisory_table.items():
        if advisory_table[key].product in product_list:
            if key in previous_advisories:
                for change in product_advisory.list_changes(previous_advisories[key]):
                    if debug_it or True:
                        attribute, new_value, old_value = change
                        print_to_log(key + ' attribute ' + attribute + ' Changed from ' + str(old_value) + ' to ' + str(new_value))

column_list = [('Advisory ID', 'ntap_advisory_id', 20),
               ('Title', 'title', 50),
               ('Product', 'product', 17),
               ('Status', 'product_status', 17),
               ('CVEs', 'cves', 22),
               ('Description', 'summary', 48),
               ('Fix Links', 'fixes', 62),
               ('First Fixed in Release', 'first_fixed', 13),
               ('Notes', 'notes', 26),
               ('Version', 'version', 11),
               ('Date', 'date', 11),
               ('Comment', 'comment', 26),
               ('Workarounds', 'workarounds', 26),
               ]

time_stamp = time.strftime("%H%M%S")
workbook = xlsxwriter.Workbook(output_file + time_stamp + '.xlsx')
worksheet = workbook.add_worksheet('Advisories')
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
    if advisory_table[key].product in product_list:
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
                worksheet.write_string(row, col, str(advisory_table[key].__getattribute__(attribute_name)), fill_yellow_format)
            else:
                worksheet.write_string(row, col, str(advisory_table[key].__getattribute__(attribute_name)), data_cell_format)
            col += 1
        row += 1
    col = 0

worksheet.autofilter(0, 0, row-1, len(column_list)-1)

logsheet = workbook.add_worksheet('Logging')
row = 0
col = 0
for log in logs:
    logsheet.write_string(row, col, log)
    row += 1

workbook.close()

with sg.FlexForm('NetApp Security Advisories Summary v1.0') as form:
    form_rows = [[sg.Text('NetApp Security Advisories Summary saved as ' + output_file + time_stamp + '.xlsx', size=(60, 1))],
                 [sg.Text('Open now?', size=(50, 1))],
                 [sg.Ok(), sg.Cancel()]]

    button, values = form.LayoutAndShow(form_rows)

if button == 'Ok':
    if platform.system() == "Darwin":
        # mac
        os.system("open " + output_file + time_stamp + '.xlsx.')
    else:
        # pc
        os.system("start " + output_file + time_stamp + '.xlsx.')


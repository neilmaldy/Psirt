import requests
from bs4 import BeautifulSoup
import os
import json

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

advisory = []
for f in os.listdir('.'):
    if f.endswith('.json'):
        with open (f, 'r') as fp:
            advisory.append(json.loads(fp.read()))

advisory_table =  []
for adv in advisory:
    for product in adv['kb_affected_list']:
        product_advisory = {}
        product_advisory['product'] = product
        product_advisory['ntap_advisory_id'] = adv['ntap_advisory_id']
        product_advisory['kb_title'] = adv['kb_title']
        product_advisory['kb_summary'] = adv['kb_summary']
        cves = []
        for cve in adv['kb_scoring_calc']:
            cves.append(cve + ' ' + adv['kb_scoring_calc'][cve]['score'] + ' ' + adv['kb_scoring_calc'][cve]['range'])
        product_advisory['cves'] = cves
        fixes = []
        for fix in adv['kb_fixes']:
            if fix['product'] == product:
                if 'fixes' in fix:
                    for fix_link in fix['fixes']:
                        if 'link' in fix_link:
                            fixes.append(fix_link['link'])
                        else:
                            if fix['wontfix'] == 'true':
                                fixes.append('WONT_FIX')
                            else:
                                fixes.append('')
        product_advisory['kb_fixes'] = fixes
        advisory_table.append(product_advisory)

for product_advisory in advisory_table:
    print(product_advisory['ntap_advisory_id'] + ':' + product_advisory['product'])


print('Done.')
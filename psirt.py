import requests
from bs4 import BeautifulSoup
import os
import json

root_url = 'https://security.netapp.com/data/advisory/'
response = requests.get(root_url)
data = response.text
soup = BeautifulSoup(data, 'lxml')

for link in soup.find_all('a'):
    if link.get('href').endswith('.json'):
        print(link.get('href'))
        adv = requests.get(root_url + link.get('href'))
        open(link.get('href'), 'wb').write(adv.content)
        break
advisory = []
for f in os.listdir('.'):
    if f.endswith('.json'):
        with open (f, 'r') as fp:
            advisory.append(json.loads(fp.read()))

print('Done.')
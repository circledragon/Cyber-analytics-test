import whois
import pandas as pd
from selenium import webdriver
from extract_info import extract_information


URL = 'https://securelist.com/apt-phantomlance/96772/'
driver = webdriver.Chrome()
column_names = ['Number',
                'domain_name',
                'registrar',
                'whois_server',
                'referral_url',
                'updated_date',
                'creation_date',
                'expiration_date',
                'name_servers',
                'status',
                'emails',
                'dnssec',
                'name',
                'org',
                'address',
                'city',
                'state',
                'zipcode',
                'country']

result_df = pd.DataFrame(columns = column_names)

print("Extracting information from : {}".format(URL))
(hash_result, domain_result, ip_result) = extract_information(URL, driver)
#print(domain_result)
with open('ip_address.txt', 'w') as f:
    for address in ip_result:
        f.write("{}\n".format(address))
with open("hash.txt", 'w') as f:
    for hashes in hash_result:
        f.write("{}\n".format(hashes))

i = 1
for domain in domain_result:
    print('Finding whois of : {}'.format(domain))
    try:
        data = whois.whois(domain) 
        temp_df = pd.DataFrame(dict([(k,pd.Series(v)) for k,v in data.items()]))
        temp_df['Number'] = pd.Series( [i for x in range(temp_df.shape[0])] ) 
        result_df = result_df.append(temp_df)
        i += 1

    except whois.parser.PywhoisError:
        pass

result_df = result_df[column_names]

result_df.to_csv("whois_information.csv", index = False)

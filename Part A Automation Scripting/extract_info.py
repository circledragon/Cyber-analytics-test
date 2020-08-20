from selenium import webdriver
from bs4 import BeautifulSoup
import pandas as pd
import re



def extract_information(web_url, driver):
    '''
    This uses selenium to get the webiste
    BeautifulSoup is used to parse the html
    regex is used to extract the various informations 
    '''

    URL = web_url

    ip_result = []
    domain_result = []
    hash_result = []
    dataframes = []

    driver.get(URL)

    #stages = driver.find_elements_by_class_name('table-wrapper')
    soup = BeautifulSoup(driver.page_source, 'html.parser')
    # entry-content contains main contents of the report
    result = soup.find('div', class_ = 'entry-content')
    textlines = result.get_text().split("\n")

    # for domain
    regex_domain = "[\w\.]+\[\.\][a-zA-Z]+"

    # for ip address
    regex_ip = re.compile(r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){2}" 
    r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\[\.\])" 
    r"(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)")
    
    # for md5 hash
    regex_md5 = "[0123456789abcdef]{32}"

    for line in textlines:

        hashes = re.findall(regex_md5, line)
        domains = re.findall(regex_domain, line)
        ip = re.findall(regex_ip, line)

        for item in hashes:
            hash_result.append(item)
        for item in domains:
            domain_result.append(re.sub(r"[\[\]]", "", item))
        for item in ip:
            ip_result.append(re.sub(r"[\[\]]", "", item))

    driver.close()

    return (hash_result, domain_result, ip_result)



# Part A Automation Scripting


Before running ensure that you are already in the environment via:
```
conda activate <environment name>
```

The driver used for selenium to develop the code is included here in "chromedriver_win32.zip" but other drivers should work. 

To run code simply use:
```
python whoisinfo.py
```

The results will be saved in 3 different files:<br>
"hash.txt" : stores the hashes found<br>
"ip_address.txt": stores the ip addresses found<br>
"whois_information.csv": stores the domains as well as their whois information<br>


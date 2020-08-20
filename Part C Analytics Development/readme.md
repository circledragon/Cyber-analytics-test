# Part C Analytics Development

Ensure that the **http.log file is unzipped** first before running code.  Also ensure that you are already in the environment via:
```
conda activate <environment name>
```

To run code simply use:
```
python find_recon.py
```

The code does the following:
1. Load data
2. Check for reconnaissance activity from each IP address
3. Calculate score

**1. Load Data** <br>
Data is loaded from the http.log and headers are added in as well.
Headers can be found at: http://www.secrepo.com/Datasets%20Description/Network/http.html
Description of the headers can be found at: http://gauss.ececs.uc.edu/Courses/c6055/pdf/bro_log_vars.pdf

**2. Check for reconnaissance activity from each IP address**<br>
Following the above links, the incoming IP address can be found in the "id.orig_h" column. To check if reconnaissance activity is occuring, the following are checked from each IP address:<br>
a. Check if SQL injection attempt is detected under the "tags" column<br>
b. Check if the standard HTTP methods are used. This is found under "method" column<br>
c. The average amount of activity per second. This is based on the total rows of data divided by the range in "ts" column.<br>
<br>
For a and b, it assumes that as long as one "bad" action is taken, the IP address is suspicious. For c, it assumes that IP addresses with large volume of activity is attempting to perform reconnaissance.

**3. Calculate score**<br>
A score is calculated by combining the above 3. <br>
For a and b, +1 score is added to the IP address if each is detected respectively. For c, it is assumed that the average amount of activity per second is normally distributed. Using statistics, the mean and standard deviation across all IP addresses is calculated. If the value exceeds the mean + 2 * standard deviation, this is a rare event with < 2.5% chance of occuring. A score of +1 will be given to the IP address if this is the case. <br>
<br>
This means that each IP address can have a score between 0 and 3. The higher the score, the more likely that the IP address is performing reconnaissance.<br>
<br>
The final output is a csv file called "result.csv". It will show the IP addresses, results found in part 2, as well as the score. 


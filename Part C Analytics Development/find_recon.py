import pandas as pd

'''
The code looks for 3 different things
for each ip address it will check
If the SQL injection tag 'HTTP::URI_SQLI' is present
If the http method used is not standard
If the particular ip address in question has taken very frequent actions on server

It will give add a score to the ip address for each of the above
The higher the score the more suspicious the ip address is
'''

column_names = ["ts",
"uid",
"id.orig_h",
"id.orig_p",
"id.resp_h",
"id.resp_p",
"trans_depth",
"method",
"host",
"uri",
"referrer",
"user_agent",
"request_body_len",
"response_body_len",
"status_code",
"status_msg",
"info_code",
"info_msg",
"filename",
"tags",
"username",
"password",
"proxied",
"orig_fuids",
"orig_mime_types",
"resp_fuids",
"resp_mime_types"]

data = pd.read_csv("http.log", sep = "\t", names = column_names,error_bad_lines = False)
result = pd.DataFrame(columns = ["IP address", "injection tag", "bad method", "average actions per second"])

# list of http methods from https://tools.ietf.org/html/rfc2616#section-9
http_methods = [
"GET",
"HEAD",
"POST",
"PUT",
"DELETE",
"CONNECT",
"OPTIONS",
"TRACE",
"PATCH"
]

# tag for sql injection
sql_injection_tag = 'HTTP::URI_SQLI'

# set flags for injection and bad methods
current_injection_tag = 0
current_bad_method = 0
# loop through the incoming ip addresses
print("Looping through incoming ip addresses")
for incoming_ip in data['id.orig_h'].unique():

    temp = data.loc[data['id.orig_h'] == incoming_ip]
    num_rows = temp.shape[0]
    time_range = temp['ts'].max() - temp['ts'].min()

    if num_rows == 1:
        # if only taken 1 action, take average as 0
        avg_action = 0
    else:
        avg_action = num_rows/time_range

    # check if ip address has attempted SQL injection
    if sql_injection_tag in temp['tags'].unique():
        current_injection_tag = 1
    
    # check if the HTTP methods used are not in the standard list
    for method in temp['method'].unique():
        if not(method in http_methods):
            current_bad_method = 1
            break
    
    # append to result and reset flags
    result = result.append({"IP address": incoming_ip, "injection tag": current_injection_tag, "bad method": current_bad_method,
                            "average actions per second": avg_action}, ignore_index = True)
    current_injection_tag = 0
    current_bad_method = 0

# assuming a normal distribution for average action per second
# set threshold to be mean + 2*std
threshold = result['average actions per second'].mean() + \
            2 * result['average actions per second'].std() 

# to calculate score
def calculate_score(row):
    if row['average actions per second'] >= threshold:
        return row['injection tag'] + row['bad method'] + 1
    else:
        return row['injection tag'] + row['bad method']

print("calculating score")
result['score'] = result.apply(calculate_score, axis = 1)
result = result.sort_values(by = "score", ascending = False)

result.to_csv("result.csv", index = False)
print('done')


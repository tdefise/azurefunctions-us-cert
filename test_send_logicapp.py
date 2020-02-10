import requests
import json

data = {}
data['usable'] = 'true'
data['tlpLevel'] = 'white'
data['lastReportedDateTime'] = 'zzzz'
data['description'] = 'ssss'

json_data = json.dumps(data)

r = requests.post('https://prod-126.westeurope.logic.azure.com:443/workflows/8ce1b4156a7b4142b2ab170bb5d07410/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=KJnLT4rOZ7u6wZqv-tEoX_0W3TMjNKYig8ExYdY-v5U', json=json_data)
print (r.status_code)
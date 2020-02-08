import json
import logging
import os
import sys
import adal

def turn_on_logging():
    logging.basicConfig(level=logging.DEBUG)
    #or,
    #handler = logging.StreamHandler()
    #adal.set_logging_options({
    #    'level': 'DEBUG',
    #    'handler': handler
    #})
    #handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))

# You can provide account information by using a JSON file. Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
#
# The information inside such file can be obtained via app registration.
# See https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
#
# {
#    "resource": "YOUR_RESOURCE",
#    "tenant" : "YOUR_SUB_DOMAIN.onmicrosoft.com",
#    "authorityHostUrl" : "https://login.microsoftonline.com",
#    "clientId" : "YOUR_CLIENTID",
#    "clientSecret" : "YOUR_CLIENTSECRET"
# }


parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.environ.get('ADAL_SAMPLE_PARAMETERS_FILE'))

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    sample_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

authority_url = (sample_parameters['authorityHostUrl'] + '/' +
                 sample_parameters['tenant'])
GRAPH_RESOURCE = '00000002-0000-0000-c000-000000000000'
RESOURCE = sample_parameters.get('resource', GRAPH_RESOURCE)

#uncomment for verbose log
#turn_on_logging()

### Main logic begins
context = adal.AuthenticationContext(
    authority_url, validate_authority=sample_parameters['tenant'] != 'adfs',
    )

token = context.acquire_token_with_client_credentials(
    RESOURCE,
    sample_parameters['clientId'],
    sample_parameters['clientSecret'])
### Main logic ends

print('Here is the token:')
print(json.dumps(token, indent=2))


"""
tenantid = "4ddebe48-b90a-4bae-963a-05d779dcb7f4"
audience = "https://graph.microsoft.com"
clientid = "0dc05ab2-edc2-4e95-b4a7-beb7ce28a0cb"

url = "https://login.microsoftonline.com/4ddebe48-b90a-4bae-963a-05d779dcb7f4/oauth2/authorize?" \
    + "client_id=" + clientid \
    + "&response_type=id_token" \
    + "&redirect_uri=" + audience \
    + 



GET https://login.microsoftonline.com/689c417e-2596-4b1e-ad56-976712af76a1/oauth2/authorize?
client_id=52342c78-c557-48ef-8f09-be40c2093edf
&response_type=id_token
&redirect_uri=http%3A%2F%2Flocalhost%3A4200
&state=b597dbdf-7c80-4aa2-bb4e-6e76a100cffe
&client-request-id=9905b985-ae8a-4e0b-9c41-b40a4d301672
&x-client-SKU=Js&x-client-Ver=1.0.17
&nonce=7362CAEA-9CA5–4B43–9BA3–34D7C303EBA7

"""
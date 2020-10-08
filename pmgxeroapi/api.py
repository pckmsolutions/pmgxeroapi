import requests
from urllib3.exceptions import HTTPError
from functools import partial

base_url = 'https://api.xero.com/api.xro/2.0'

class XeroApi:
    def __init__(self, access_token, xero_tenant_id):
        hdrs = headers(access_token, xero_tenant_id)

        def resp_wrap(f):
            def wrapper(*args, **kwargs):
                resp = f(*args, **kwargs)
                if not resp.ok:
                    resp.raise_for_status()
                return resp.json()
            return wrapper

        self.get = resp_wrap(partial(requests.get, headers=hdrs))
        self.post = resp_wrap(partial(requests.post, headers=hdrs))

    def get_invoices(self):
        page_number = 1
        while True:
           resp = self.get(self._path(f'Invoices?page={page_number}'))
           if not resp['Invoices']:
               return
           yield resp
           page_number += 1

    def get_invoice(self, invoice_number):
        json = self.get(self._path(f'Invoices/{invoice_number}'))
        return json['Invoices'][0]

    def update_invoice(self, invoice_number, updates):
        return self.post(self._path(f'Invoices/{invoice_number}'), json=updates)

    def _path(self, suffix):
        return base_url + '/' + suffix

def headers(access_token, xero_tenant_id=None):
    hdrs = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
            }
    if xero_tenant_id is not None:
        hdrs['xero-tenant-id'] = xero_tenant_id 

    return hdrs

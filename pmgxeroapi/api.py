import requests
from functools import partial

class XeroApi:

    def __init__(self, base_url, access_token, xero_tenant_id):
        self.base_url = base_url
        self.get = partial(requests.get, headers=self._headers(access_token, xero_tenant_id))

    def get_invoices(self):
        page_number = 1
        while True:
           yield self.get(self._path(f'Invoices?page={page_number}'))
           page_number += 1

    def _path(self, suffix):
        return self.base_url + '/' + suffix

    def _headers(self, access_token, xero_tenant_id):
        return {
            'xero-tenant-id': xero_tenant_id,
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
                }


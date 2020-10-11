import requests
from functools import partial
from logging import getLogger

logger = getLogger(__name__)

base_url = 'https://api.xero.com/api.xro/2.0'

class XeroApi:
    def __init__(self, access_token, tenant_id, handle_reconnect=None):
        self.tenant_id = tenant_id
        self._set_callers(access_token, handle_reconnect)

    def _set_callers(self, access_token, handle_reconnect):
        hdrs = headers(access_token, self.tenant_id)
        self.get = self._resp_wrap(partial(requests.get, headers=hdrs), handle_reconnect)
        self.post = self._resp_wrap(partial(requests.post, headers=hdrs), handle_reconnect)

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

    def _resp_wrap(self, f, handle_reconnect):
        def wrapper(*args, **kwargs):
            resp = f(*args, **kwargs)
            if resp.ok:
                return resp.json()

            if handle_reconnect is None:
                resp.raise_for_status()

            if resp.status_code != requests.status_codes.codes['unauthorized']:
                resp.raise_for_status()

            logger.warning('Request unauthorised - attempting to reconnect')

            access_token = handle_reconnect()
            if not access_token:
                resp.raise_for_status()
            self._set_callers(access_token, handle_reconnect)

            # try again
            resp = f(*args, **kwargs)
            if not resp.ok:
                resp.raise_for_status()
            return resp.json()

        return wrapper

def headers(access_token, xero_tenant_id=None):
    hdrs = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
            }
    if xero_tenant_id is not None:
        hdrs['xero-tenant-id'] = xero_tenant_id 

    return hdrs

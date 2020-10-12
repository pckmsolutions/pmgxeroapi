from logging import getLogger
import requests

logger = getLogger(__name__)

base_url = 'https://api.xero.com/api.xro/2.0'

class XeroApi:
    def __init__(self, aiohttp_session, access_token, tenant_id, handle_reconnect=None):
        self.aiohttp_session = aiohttp_session
        self.tenant_id = tenant_id
        self._set_callers(access_token, handle_reconnect)

    def _set_callers(self, access_token, handle_reconnect):
        hdrs = headers(access_token, self.tenant_id)
        self.get = self._resp_wrap(self.aiohttp_session.get,hdrs, handle_reconnect)
        self.post = self._resp_wrap(self.aiohttp_session.post, hdrs, handle_reconnect)

    async def get_invoices(self):
        page_number = 1
        while True:
           resp = await self.get(self._path(f'Invoices?page={page_number}'))
           if not resp['Invoices']:
               return
           yield resp
           page_number += 1

    async def get_invoice(self, invoice_number):
        json = await self.get(self._path(f'Invoices/{invoice_number}'))
        return json['Invoices'][0]

    async def update_invoice(self, invoice_number, updates):
        return await self.post(self._path(f'Invoices/{invoice_number}'), json=updates)

    def _path(self, suffix):
        return base_url + '/' + suffix

    def _resp_wrap(self, f, headers, handle_reconnect):
        async def wrapper(*args, **kwargs):
            resp = await f(*args, headers=headers, **kwargs)
            if resp.status == 200:
                return await resp.json()

            if handle_reconnect is None:
                resp.raise_for_status()

            if resp.status != requests.status_codes.codes['unauthorized']:
                resp.raise_for_status()

            logger.warning('Request unauthorised - attempting to reconnect')

            access_token = handle_reconnect()
            if not access_token:
                resp.raise_for_status()
            self._set_callers(access_token, handle_reconnect)

            # try again
            resp = await f(*args, headers=headers, **kwargs)
            if resp.status == 200:
                resp.raise_for_status()
            return await resp.json()

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

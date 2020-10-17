from logging import getLogger
from pmgaiorest import ApiBase

logger = getLogger(__name__)

BASE_URL = 'https://api.xero.com/api.xro/2.0'

class XeroApi(ApiBase):
    def __init__(self, aiohttp_session, header_args, handle_reconnect=None):
        super().__init__(aiohttp_session, BASE_URL, header_args,
                handle_reconnect=handle_reconnect)

    def create_headers(self, **kwargs):
        headers = super().create_headers(**kwargs)
        xero_tenant_id = kwargs.get('xero_tenant_id')
        if xero_tenant_id is not None:
            headers['xero-tenant-id'] = xero_tenant_id 
        return headers

    async def get_invoices(self):
        page_number = 1
        while True:
           resp = await self.get(f'Invoices?page={page_number}')
           if not resp['Invoices']:
               return
           yield resp
           page_number += 1

    async def get_invoice(self, invoice_number):
        json = await self.get(f'Invoices/{invoice_number}')
        return json['Invoices'][0]

    async def update_invoice(self, invoice_number, updates):
        return await self.post(f'Invoices/{invoice_number}', json=updates)

    async def get_connections(self):
        return await self.get(None, full_path=f'connections')


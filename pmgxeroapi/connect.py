from concurrent.futures import ThreadPoolExecutor
import socketserver
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
import webbrowser
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client.errors import OAuthError
from functools import partial
from queue import Queue
from contextlib import ExitStack
from logging import getLogger
from aiohttp.web_exceptions import HTTPUnauthorized
import asyncio

from .api import XeroApi
from .exceptions import MultipleTenantError, InvalidTenantError

logger = getLogger(__name__)
PORT = 8080

class XeroConnect:
    def __init__(self, aiohttp_session, *,
            token_endpoint,
            authorization_endpoint,
            client_id,
            client_secret,
            scope,
            new_token_callable = None,
            tenant_id = None):
        self.aiohttp_session = aiohttp_session
        self.token_endpoint = token_endpoint
        self.authorization_endpoint = authorization_endpoint
        self.new_token_callable = new_token_callable
        self.new_oauth_client  = partial(OAuth2Session, client_id, client_secret, scope=scope)
        self.token_config = None
        self.tenant_id = tenant_id

    async def cli_connect(self):
        '''
        '''
        client = self.new_oauth_client(token_endpoint_auth_method='client_secret_post')
        redirect_uri = f'http://localhost:{PORT}/callback'
    
        uri, state = client.create_authorization_url(self.authorization_endpoint,
                redirect_uri=redirect_uri)
    
        authorization_response = get_auth_response(uri)
        if not authorization_response:
            return None
    
        self.token_config = client.fetch_token(self.token_endpoint,
                authorization_response=authorization_response,
                redirect_uri=redirect_uri)
    
        return await self.connect()

    async def conf_connect(self, config):
        self.token_config = config
        return await self.connect()

    async def connect(self):
        '''
        Connect using the given config - which is returned from 
        a normal connect cli_connect
        If this fails, it tries to use the refresh token.
        If that fails, it raises the first exception
        '''
        def _handle_reconnect():
            client = self.new_oauth_client()
            try:
                logger.info('Reconnecting using refresh token.')
                self.token_config = client.refresh_token(self.token_endpoint,
                        refresh_token=self.token_config['refresh_token'])
                if self.new_token_callable:
                    self.new_token_callable(self.token_config)
                #return {'access_token': self.token_config['access_token']}
                return self._header_args(access_token=self.token_config['access_token'])
            except OAuthError as e:
                logger.error(f'Failed to reconnect using refresh token {e}')
                return None

        xero = XeroApi(self.aiohttp_session,
                self._header_args(
                    access_token=self.token_config['access_token']),
                handle_reconnect=_handle_reconnect)

        tenants = await xero.get_connections()

        if self.tenant_id == None:
            if len(tenants) > 1:
                raise MultipleTenantError(connections=tenants)
            else:
                self.tenant_id = tenants[0]['tenantId']
        if not self.tenant_id in [t['tenantId'] for t in tenants]:
            raise InvalidTenantError()

        xero.update_header_args(self._header_args(
                    access_token=self.token_config['access_token']))

        return xero

    def _header_args(self, *, access_token):
        return {'access_token': access_token, 'xero_tenant_id': self.tenant_id}

def get_auth_response(auth_uri):
    '''
    creates a server to handle the auth callback
    opens the browser to authenticate and authorise
    '''
    response = Queue()

    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            response.put(self.path)
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b'You may now close this browser window.')
            self.wfile.flush()
        def log_message(self, format, *args):
            logger.info(format % args)

    socketserver.TCPServer.allow_reuse_address = True

    authorization_response = None
    
    with ExitStack() as stack:
        ex = stack.enter_context(ThreadPoolExecutor())
        server = stack.enter_context(socketserver.TCPServer(("", PORT), RequestHandler))

        res = ex.submit(server.serve_forever)

        print('Xero: Please authorise using the browser.')
        logger.debug('Opening browser for %s', auth_uri)

        webbrowser.open_new(auth_uri)

        try:
            authorization_response = response.get()
        except KeyboardInterrupt:
            pass

        server.shutdown()

    return authorization_response # which may be null

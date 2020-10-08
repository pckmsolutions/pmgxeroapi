from concurrent.futures import ThreadPoolExecutor
import socketserver
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
import webbrowser
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client.errors import OAuthError
import requests
from requests.exceptions import HTTPError
from functools import partial
from queue import Queue
from contextlib import ExitStack
from logging import getLogger

from .api import XeroApi, headers 
from .exceptions import MultipleTenantError, InvalidTenantError

logger = getLogger(__name__)
PORT = 8080

token_endpoint = 'https://identity.xero.com/connect/token'
connections_endpoint = 'https://api.xero.com/connections'
authorization_endpoint = 'https://login.xero.com/identity/connect/authorize'

class XeroConnect:
    def __init__(self, client_id, client_secret, scope):
        self.new_oauth_client  = partial(OAuth2Session, client_id, client_secret, scope=scope)
        self.token_config = None

    def cli_connect(self, tenant_id=None):
        '''
        '''
        client = self.new_oauth_client(token_endpoint_auth_method='client_secret_post')
        redirect_uri = f'http://localhost:{PORT}/callback'
    
        uri, state = client.create_authorization_url(authorization_endpoint,
                redirect_uri=redirect_uri)
    
        authorization_response = get_auth_response(uri)
        if not authorization_response:
            return None
    
        self.token_config = client.fetch_token(token_endpoint,
                authorization_response=authorization_response,
                redirect_uri=redirect_uri)
    
        return self.connect(tenant_id)

    def conf_connect(self, config, tenant_id=None):
        self.token_config = config
        return self.connect(tenant_id)

    def connect(self, tenant_id=None):
        '''
        Connect using the given config - which is returned from 
        a normal connect cli_connect
        If this fails, it tries to use the refresh token.
        If that fails, it raises the first exception
        '''
        def _handle_reconnect():
            client = self.new_oauth_client()
            try:
                logger.info('Using refresh token.')
                self.token_config = client.refresh_token(token_endpoint,
                        refresh_token=self.token_config['refresh_token'])
                return self.token_config
            except OAuthError as e:
                logger.error(f'Failed to reconnect using refresh token {e}')
                return None

        try:
            tenant_id = check_tenant_id(self.token_config, tenant_id)
        except HTTPError as e:
            if e.response.status_code != requests.status_codes.codes['unauthorized']:
                raise

        _handle_reconnect()
    
        return XeroApi(self.token_config['access_token'], tenant_id,
                handle_reconnect=_handle_reconnect)

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

    socketserver.TCPServer.allow_reuse_address = True

    authorization_response = None
    
    with ExitStack() as stack:
        ex = stack.enter_context(ThreadPoolExecutor())
        server = stack.enter_context(socketserver.TCPServer(("", PORT), RequestHandler))

        res = ex.submit(server.serve_forever)

        print('Please authorise using the browser.')
        logger.debug('Opening browser for %s', auth_uri)

        webbrowser.open_new(auth_uri)

        try:
            authorization_response = response.get()
        except KeyboardInterrupt:
            pass

        server.shutdown()

    return authorization_response # which may be null

def check_tenant_id(token_response, tenant_id=None):
    '''
    Calls the connections endpoint.
    If given a tenant_id it checks if it's valid
    Else if only one tenant, it uses that.
    Else it raises an error
    '''
    resp = requests.get(connections_endpoint,
            headers=headers(token_response['access_token']))
    if not resp.ok:
        resp.raise_for_status()

    connections = resp.json()

    if tenant_id == None:
        if len(connections) > 1:
            raise MultipleTenantError(connections=connections)
        else:
            return connections[0]['tenantId']
    if not tenant_id in [c['tenantId'] for c in connections]:
        raise InvalidTenantError()

    return tenant_id


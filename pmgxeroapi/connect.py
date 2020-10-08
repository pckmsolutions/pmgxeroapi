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

from .api import XeroApi, headers 
from .exceptions import MultipleTenantError, InvalidTenantError

PORT = 8080

client_id = '4B3C0605324F48348668551239500A0D'
client_secret = 'mILu99MA-HtprWarrQ40mj5w3bo7LFIxNd6r_c8FG64oCfkp'
scope = 'offline_access accounting.transactions'
token_endpoint = 'https://identity.xero.com/connect/token'
connections_endpoint = 'https://api.xero.com/connections'
authorization_endpoint = 'https://login.xero.com/identity/connect/authorize'

new_oauth_client  = partial(OAuth2Session, client_id, client_secret, scope=scope)

def cli_connect(tenant_id=None):
    '''
    connect returns XeroApi and the config used to connect
    '''
    client = new_oauth_client(token_endpoint_auth_method='client_secret_post')
    redirect_uri = f'http://localhost:{PORT}/callback'

    uri, state = client.create_authorization_url(authorization_endpoint,
            redirect_uri=redirect_uri)

    authorization_response = get_auth_response(uri)
    if not authorization_response:
        return None

    token_response = client.fetch_token(token_endpoint,
            authorization_response=authorization_response,
            redirect_uri=redirect_uri)

    tenant_id = check_tenant_id(token_response, tenant_id)

    return XeroApi(token_response['access_token'], tenant_id), token_response

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

        webbrowser.open_new(auth_uri)

        try:
            authorization_response = response.get()
        except KeyboardInterrupt:
            pass

        server.shutdown()

    return authorization_response # which may be null

def connect_from_config(config, tenant_id=None):
    '''
    Connect using the given config - which is returned from 
    a normal connect cli_connect
    If this fails, it tries to use the refresh token.
    If that fails, it raises the first exception
    '''
    try:
        return XeroApi(config['access_token'], check_tenant_id(config, tenant_id))
    except HTTPError as e:
        if e.response.status_code != requests.status_codes.codes['unauthorized']:
            raise
        auth_error = e

    # auth failed - try to refresh
    client = new_oauth_client()
    try:
        print('Using refresh token')
        client.refresh_token(token_endpoint, refresh_token=config['refresh_token'])
    except OAuthError:
        raise auth_error

    return XeroApi(config['access_token'], check_tenant_id(config, tenant_id))

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


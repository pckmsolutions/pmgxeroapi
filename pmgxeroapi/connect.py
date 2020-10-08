from concurrent.futures import ThreadPoolExecutor
import socketserver
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
import webbrowser
from authlib.integrations.requests_client import OAuth2Session
import json

from .api import XeroApi

PORT = 8080

client_id = '4B3C0605324F48348668551239500A0D'
client_secret = 'mILu99MA-HtprWarrQ40mj5w3bo7LFIxNd6r_c8FG64oCfkp'
scope = 'offline_access accounting.transactions openid profile email accounting.contacts accounting.settings'

def _serve():
    requested = ''
    socketserver.TCPServer.allow_reuse_address = True

    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal requested
            requested = self.path
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b'You may now close this browser window.')
            self.wfile.flush()
    
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        httpd.handle_request()

    return requested

def _prompt(uri):
    webbrowser.open_new(uri)

def connect_from_config(config, base_url, xero_tenant_id):
    with open(config, 'r') as f:
        token_response = json.load(f)
    return XeroApi(base_url, token_response['access_token'], xero_tenant_id)

def cli_connect(base_url, xero_tenant_id, persist=None):
    client = OAuth2Session(client_id, client_secret, scope=scope,
            token_endpoint_auth_method='client_secret_post')
    authorization_endpoint = 'https://login.xero.com/identity/connect/authorize'
    redirect_uri = f'http://localhost:{PORT}/callback'

    uri, state = client.create_authorization_url(authorization_endpoint,
            redirect_uri=redirect_uri)

    with ThreadPoolExecutor() as ex:
        res = ex.submit(_serve)
        _prompt(uri)

        authorization_response = res.result()

        token_endpoint = 'https://identity.xero.com/connect/token'
        
        token_response = client.fetch_token(token_endpoint,
                authorization_response=authorization_response,
                redirect_uri=redirect_uri)

        print('Connecting with access_token: ', token_response['access_token']) 
        if persist:
            with open(persist, 'w') as f:
                json.dump(token_response, f)

        return XeroApi(base_url, token_response['access_token'], xero_tenant_id)


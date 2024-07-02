from spin_sdk.http import IncomingHandler, Request, Response, send
from spin_sdk.variables import variables
import logging
import base64
import hashlib
import hmac
import datetime
from email.utils import formatdate
from urllib.parse import parse_qs, urlparse


class AZCredentials:
    def __init__(self, account_name: str, account_key: str, service: str) -> None:
        self.account_name: str = account_name
        self.service: str = service

        try:
            self.account_key: bytes = base64.b64decode(account_key)
        except Exception as e:
            logging.fatal(f"Unable to base64 decode account_key{e}")


class IncomingHandler(IncomingHandler):
    def handle_request(self, request: Request) -> Response:
        try:
            account_name = variables.get("az_account_name")
            shared_key = variables.get("az_shared_key")
        except Exception as e:
            return Response(
                200,
                {"content-type": "text/plain"},
                f"Unable to read environment variables: {e}".encode('utf-8')
            )
        
        service = request.headers.get("x-az-service")
        if not service:
            return Response(
                200,
                {"content-type": "text/plain"},
                "ERROR: You must include the 'x-az-service' with your request.".encode('utf-8')
            )

        parsed_url = urlparse(request.uri)
        uri_path = parsed_url.path
        query_string = parsed_url.query
        endpoint = f"https://{account_name}.{service}.core.windows.net"

        if len(query_string) == 0: 
            if uri_path == "/":
                return Response(
                    200,
                    {"content-type": "text/plain"},
                    "Error: If you are not including a query string, you must have a more specific URI path (i.e. /container_name/path/to/object)".encode('utf-8')
                )
            else:
                endpoint += uri_path
        else:
            endpoint += uri_path + "?" + query_string

        now = datetime.datetime.now(datetime.timezone.utc)

        body_bytes = request.body
        if body_bytes is None:
            body_bytes = b''

        new_req = Request(request.method, endpoint, {}, body_bytes)

        try:
            response = send_azure_request(new_req, now, account_name, shared_key, service)
            return Response(
                response.status,
                response.headers,
                response.body
            )
        except Exception as e:
            return Response(
                200,
                {"content-type": "text/plain"},
                f"Error sending request to Azure: {e}".encode('utf-8')
            )
    

def compute_HMAC_SHA256(c: AZCredentials, message: str) -> str:
    h = hmac.new(c.account_key, message.encode('utf-8'), hashlib.sha256)
    return base64.b64encode(h.digest()).decode('utf-8')


def build_string_to_sign(c: AZCredentials, req: Request) -> str:
	# Returns a blank value if the header value doesn't exist
    def get_header(key: str, headers: dict) -> str:
        value = headers.get(key)
        if value == None:
            return ""
        return value
    
	# Per the documentation, the Content-Length field must be an empty string if the content length of the request is zero.    
    content_length = get_header("content-length", req.headers)
    if content_length == '0':
        content_length = ""
    
    canonicalized_resource = build_canonicalized_resource(c, req.uri)
    canonicalized_header = build_canonicalized_header(req.headers)

    return "\n".join([
        req.method, 
        get_header("content-encoding", req.headers),
        get_header("content-language", req.headers), 
        content_length,
        get_header("content-md5", req.headers),
        get_header("content-type", req.headers),
        "", # Empty date because x-ms-date is expected
        get_header("if-modified-since", req.headers),
        get_header("if-match", req.headers),
        get_header("if-none-match", req.headers),
        get_header("if-unmodified-since", req.headers),
        get_header("range", req.headers),
        canonicalized_header,
        canonicalized_resource
    ])


def build_canonicalized_header(headers: dict) -> str:
    canonical_headers_map = {}
    for key, value in headers.items():
        key = key.lower()
        if key.startswith("x-ms-"):
            canonical_headers_map[key] = value

    if len(canonical_headers_map) == 0:
        return ""

    key_list = []
    for key, _ in canonical_headers_map.items():
        key_list.append(key)
    key_list.sort()

    canonical_headers = ""
    for i, key in enumerate(key_list):
        if i > 0:
            canonical_headers += "\n"
        canonical_headers += f'{key}:{canonical_headers_map[key]}'

    return canonical_headers


def build_canonicalized_resource(c: AZCredentials, url: str) -> str:
    canonicalized_resource = "/" + c.account_name

    if url:
        parsed_url = urlparse(url)
        canonicalized_resource += parsed_url.path

        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            param_names = sorted(params.keys())
            for param_name in param_names:
                param_values = params[param_name]
                canonicalized_resource += f"\n{param_name.lower()}:{','.join(param_values)}"
    else:
        canonicalized_resource += "/"
    
    return canonicalized_resource


def send_azure_request(req: Request, now: datetime.datetime, account_name: str, shared_key: str, service: str) -> Response:
    creds = AZCredentials(account_name, shared_key, service)
    
	# Setting universally required headers
    req.headers["x-ms-date"] = formatdate(timeval=now.timestamp(), localtime=False, usegmt=True)
    req.headers["x-ms-version"] = "2020-10-02" # Although not technically required, we strongly recommend specifying the latest Azure Storage API version: https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services

    # Setting method and service-specific headers
    if req.method == "PUT" or req.method == "POST":
        req.headers["content-length"] = f'{len(req.body)}'
        if service == "blob":
            req.headers["x-ms-blob-type"] = "BlockBlob"

    string_to_sign = build_string_to_sign(creds, req)
    signature = compute_HMAC_SHA256(creds, string_to_sign)
    auth_header = f'SharedKey {account_name}:{signature}'

    req.headers["authorization"] = auth_header

    request = Request(req.method, req.uri, req.headers, req.body)
    
    return send(request)
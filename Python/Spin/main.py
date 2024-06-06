from spin_sdk.http import IncomingHandler, Request, Response, send
from spin_sdk.variables import variables
import datetime
import hashlib
import hmac

# This is initialized in the handle_request method
config = None


class AWSConfig:
  """
  A class to represent AWS configuration details.
  """

  def __init__(self, access_key_id, secret_access_key, session_token, region, service):
    """
    Initializes an AWSConfig object.

    Args:
      access_key_id (str): The AWS access key ID.
      secret_access_key (str): The AWS secret access key.
      session_token (str, optional): The AWS session token.
      region (str): The AWS region. 
      service (str): The specific AWS service. 
    """

    self.access_key_id = access_key_id
    self.secret_access_key = secret_access_key
    self.session_token = session_token
    self.region = region
    self.service = service
  def __str__(self):
    """
    Returns a string representation of the AWSConfig object.
    """
    return f"AWSConfig(access_key_id='{self.access_key_id}', secret_access_key='***', session_token='{self.session_token}', region='{self.region}', service='{self.service}')"
  

# Encodes a string to bytes using UTF-8 encoding
def encode(string: str) -> bytes:
    return string.encode('utf-8')


# This creates a SHA256 hash of a string/byte array and returns a hex-encoded string
def hash(payload: str|bytes) -> str:
    if isinstance(payload, str):
        payload = encode(payload)
    return hashlib.sha256(payload).digest().hex()


# Building the canonical and signed headers
def build_headers(headers: dict) -> tuple:
    # Formatted as header_key_1:header_value_1\nheader_key_2:header_value_2\n
    canonical_headers = ''
    # Formatted as header_key_1;header_key_2
    signed_headers = ''
    for key in sorted(headers.keys()):
        canonical_headers += f"{key.lower()}:{headers[key]}\n"
        if not signed_headers:
            signed_headers += key.lower()
        else:
            signed_headers += f";{key.lower()}"
    
    return (canonical_headers, signed_headers)


# The numbered functions below correspond to the 'Calculating a Signature' image in the article linked here: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
# 1. Canonical Request
def get_canonical_request(http_verb: str, canonical_uri: str, canonical_query_string: str, canonical_headers: str, signed_headers: str, unsigned_payload_hash: str) -> str:
    return '\n'.join([http_verb, canonical_uri, canonical_query_string, canonical_headers, signed_headers, unsigned_payload_hash])


# 2. StringToSign
def get_string_to_sign(canonical_request: str, now: datetime.datetime) -> str:
    return f"AWS4-HMAC-SHA256\n"\
           f"{now.strftime('%Y%m%dT%H%M%SZ')}\n"\
           f"{now.strftime('%Y%m%d')}/{config.region}/{config.service}/aws4_request\n"\
           f"{hash(canonical_request)}"


# 3. Signature
def get_signature(string_to_sign: str, now: datetime.datetime) -> str:
    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, encode(msg), hashlib.sha256).digest()

    date_key = sign(encode('AWS4'+config.secret_access_key), now.strftime('%Y%m%d'))
    date_region_key = sign(date_key, config.region)
    date_region_service_key = sign(date_region_key, config.service)
    signing_key = sign(date_region_service_key, 'aws4_request')

    return sign(signing_key, string_to_sign).hex()


def get_authorization_header(now: datetime.datetime, canonical_request: str, signed_headers: str) -> str:
    string_to_sign = get_string_to_sign(canonical_request, now)
    signature = get_signature(string_to_sign, now)
    
    return f"AWS4-HMAC-SHA256 Credential={config.access_key_id}/{now.strftime('%Y%m%d')}/{config.region}/{config.service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"


def send_aws_http_request(http_verb: str, host: str, uri_path='/', query_params={}, headers={}, payload=None) -> Response: 
    # Getting the current time in UTC
    now = datetime.datetime.now(datetime.timezone.utc)

    if http_verb in ['GET', 'DELETE', 'HEAD']:
        payload = b''
    elif not payload:
        payload = b''

    if not uri_path.startswith('/'):
        uri_path = '/' + uri_path

    # Keep in mind that these are the minimum headers required to interact with AWS. See the relevant service's API guide for any other required headers.
    headers['host'] = host
    headers['x-amz-date'] = now.strftime('%Y%m%dT%H%M%SZ')
    headers['x-amz-content-sha256'] = hash(payload)

    # session_token is optional
    if config.session_token:
        headers['x-amz-security-token'] = config.session_token

    canonical_query_string = "&".join([key + '=' + query_params[key] for key in sorted(query_params.keys())])
    canonical_headers, signed_headers = build_headers(headers)
    canonical_request = get_canonical_request(http_verb, uri_path, canonical_query_string, canonical_headers, signed_headers, headers['x-amz-content-sha256'])

    # Adding the authorization header
    headers['authorization'] = get_authorization_header(now, canonical_request, signed_headers)

    # Spin adds the host header on it's own, so we need to delete it here to avoid a duplicate header error
    del headers['host']

    return send(Request(http_verb, f"http://{host}{uri_path}", headers, payload))


class IncomingHandler(IncomingHandler):
    def handle_request(self, request: Request) -> Response:
        global config
        
        try:
            region = variables.get('aws_default_region')
            access_key = variables.get('aws_access_key_id')
            secret_key = variables.get('aws_secret_access_key')
            session_token = variables.get('aws_session_token')
            service = variables.get('aws_service')
            host = variables.get('aws_host')
        except Exception as e:
            raise ValueError(f'Error retrieving environment variables: {e}')
        
        if not all([region, access_key, secret_key, host, service]):
            raise ValueError("One or more required environment variables are missing.")
        if not session_token:
            print('The optional session_token was not included.')

        config = AWSConfig(access_key, secret_key, session_token, region, service)

        # In the case of S3, the URI path is the S3 object's prefix + key.
        uri_path = request.headers.get('uri-path', '')
        # If necessary, add query parameters: 'query_params[key] = value'
        query_params = {}
        # If necessary, add extra headers: 'headers[key] = value'
        headers = {}

        payload = request.body
        if payload is None:
            payload = b''

        try:
            response = send_aws_http_request(request.method, host, uri_path, query_params, headers, payload)
            return Response(
                response.status,
                response.headers,
                response.body
            )
        except Exception as e:
            return Response(
                200,
                {"content-type": "text/plain"},
                bytes(f"Failure: {e}", "utf-8")
            )
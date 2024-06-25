from spin_sdk.http import IncomingHandler, Request, Response, send
from spin_sdk.variables import variables
import datetime
import hashlib
import hmac


class AWSConfig:
  """
  A class to represent AWS configuration details.
  """

  def __init__(self, access_key_id: str, secret_access_key: str, session_token: str, region: str, service: str, host: str) -> None:
    """
    Args:
      access_key_id (str): The AWS access key ID.
      secret_access_key (str): The AWS secret access key.
      session_token (str, optional): The AWS session token.
      region (str): The AWS region. 
      service (str): The specific AWS service. 
      host (str): The endpoint to access the AWS Service.
    """

    self.access_key_id = access_key_id
    self.secret_access_key = secret_access_key
    self.session_token = session_token
    self.region = region
    self.service = service
    self.host = host

  def __str__(self) -> str:
    return f"AWSConfig(access_key_id='{self.access_key_id}', secret_access_key='***', session_token='{self.session_token}', region='{self.region}', service='{self.service}', host='{self.host}')"
  

class AWSFormattedDate:
    """
    A class to represent the date formats required by AWS.
    """
    def __init__(self, date: datetime.datetime) -> None:
        """
        Args: 
            date (datetime.datetime): The current datetime.
        """
        self.date = date.strftime('%Y%m%d')
        self.date_time = date.strftime('%Y%m%dT%H%M%SZ')
    def __str__(self) -> str:
        return f"AWSFormattedDate(date='{self.date}', date_time={self.date_time})"
    

# Encodes a string to bytes using UTF-8 encoding
def encode(string: str) -> bytes:
    return string.encode('utf-8')


# This creates a SHA256 hash of a string/byte array and returns a hex-encoded string
def get_hash(payload: str|bytes) -> str:
    if isinstance(payload, str):
        payload = encode(payload)
    return hashlib.sha256(payload).digest().hex()


def build_request_strings(headers: dict, query_params: dict) -> tuple:
    # Formatted as header_key_1:header_value_1\nheader_key_2:header_value_2\n
    canonical_headers = ''
    # Formatted as header_key_1;header_key_2
    signed_headers = ''
    # Header names must appear in alphabetical order
    for key in sorted(headers.keys()):
        # Each header name must use lowercase characters
        canonical_headers += f"{key.lower()}:{headers[key]}\n"
        if not signed_headers:
            signed_headers += key.lower()
        else:
            signed_headers += f";{key.lower()}"

    canonical_query_string = "&".join([key + '=' + query_params[key] for key in sorted(query_params.keys())])
    
    return (canonical_headers, signed_headers, canonical_query_string)


# The numbered functions below correspond to the image in the article linked here: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
# 1. Canonical Request
def get_canonical_request(http_verb: str, canonical_uri: str, canonical_query_string: str, canonical_headers: str, signed_headers: str, hashed_payload: str) -> str:
    return '\n'.join([http_verb, canonical_uri, canonical_query_string, canonical_headers, signed_headers, hashed_payload])


# 2. StringToSign
def get_string_to_sign(config: AWSConfig, formatted_date: AWSFormattedDate, canonical_request: str) -> str:
    scope = "/".join([formatted_date.date, config.region, config.service, "aws4_request"])
    return "\n".join(["AWS4-HMAC-SHA256", formatted_date.date_time, scope, get_hash(canonical_request)])


# 3. Signature
def get_signature(config: AWSConfig, formatted_date: AWSFormattedDate, string_to_sign: str) -> str:
    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, encode(msg), hashlib.sha256).digest()

    date_key = sign(encode('AWS4'+config.secret_access_key), formatted_date.date)
    date_region_key = sign(date_key, config.region)
    date_region_service_key = sign(date_region_key, config.service)
    signing_key = sign(date_region_service_key, 'aws4_request')

    return sign(signing_key, string_to_sign).hex()


def get_authorization_header(config: AWSConfig, formatted_date: AWSFormattedDate, canonical_request: str, signed_headers: str) -> str:
    string_to_sign = get_string_to_sign(config, formatted_date, canonical_request)
    signature = get_signature(config, formatted_date, string_to_sign)
    credential = "/".join([config.access_key_id, formatted_date.date, config.region, config.service, "aws4_request"])
    
    return f"AWS4-HMAC-SHA256 Credential={credential}, SignedHeaders={signed_headers}, Signature={signature}"


def send_aws_http_request(config: AWSConfig, http_verb: str, uri_path='/', query_params={}, headers={}, payload=None) -> Response: 
    # Getting the current time in UTC
    now = datetime.datetime.now(datetime.timezone.utc)
    formatted_date = AWSFormattedDate(now)

    if http_verb in ['GET', 'DELETE', 'HEAD']:
        payload = b''
    elif not payload:
        payload = b''

    if not uri_path.startswith('/'):
        uri_path = '/' + uri_path

    payload_hash = get_hash(payload)

    # Keep in mind that these are the minimum headers required to interact with AWS. See the relevant service's API guide for any other required headers.
    # Also keep in mind that Python automatically includes the content-length header, which is required for requests with payloads.
    headers['host'] = config.host
    headers['x-amz-date'] = formatted_date.date_time
    headers['x-amz-content-sha256'] = payload_hash
    # session_token is optional
    if config.session_token:
        headers['x-amz-security-token'] = config.session_token

    canonical_headers, signed_headers, canonical_query_string = build_request_strings(headers, query_params)
    canonical_request = get_canonical_request(http_verb, uri_path, canonical_query_string, canonical_headers, signed_headers, payload_hash)

    headers['authorization'] = get_authorization_header(config, formatted_date, canonical_request, signed_headers)

    # Spin adds the host header on it's own, so we need to delete it here to avoid a duplicate header error
    del headers['host']

    return send(Request(http_verb, f"https://{config.host}{uri_path}", headers, payload))


class IncomingHandler(IncomingHandler):
    def handle_request(self, request: Request) -> Response:
        try:
            region = variables.get('aws_default_region')
            access_key = variables.get('aws_access_key_id')
            secret_key = variables.get('aws_secret_access_key')
            session_token = variables.get('aws_session_token')
            service = variables.get('aws_service')
            host = variables.get('aws_host')
        except Exception as e:
            raise ValueError(f'Error retrieving environment variables: {e}')
        
        # Session token is not required
        if not all([region, access_key, secret_key, host, service]):
            raise ValueError("One or more required environment variables are missing.")

        config = AWSConfig(access_key, secret_key, session_token, region, service, host) 
        # uri_path = request.headers.get('x-uri-path', '')
        uri_path = request.uri
        # If necessary, add query parameters and/or extra headers
        query_params = {}
        headers = {}

        payload = request.body
        if payload is None:
            payload = b''

        try:
            response = send_aws_http_request(config, request.method, uri_path, query_params, headers, payload)
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
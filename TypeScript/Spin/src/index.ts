import { Variables, ResponseBuilder } from '@fermyon/spin-sdk';

class AWSConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
  service: string;
  host: string;

    constructor() {
      // The class variables are initialized using the Spin variable retriever 'Config'.
      let parseVariable = function(key: string): string {
        let result: string|null = Variables.get(key)
        if (typeof result == 'string') {
          return result;
        } else {
          throw new Error(`Unable to parse variable for key '${key}'. Not a string.`)
        }
      }

      this.accessKeyId = parseVariable("aws_access_key_id"); 
      this.secretAccessKey = parseVariable("aws_secret_access_key");
      this.sessionToken = parseVariable("aws_session_token");
      this.region = parseVariable("aws_default_region");
      this.service = parseVariable("aws_service");
      this.host = parseVariable("aws_host");
    }
}


class AWSFormattedDate {
  date: string;
  dateTime: string;

  /**
   * This formats the current date in the format that AWS needs.
   * 
   * @param {Date} date - The date to format.
   */
  constructor(date: Date) {
    let pad = (number: number) => number.toString().padStart(2, '0');

    let year = date.getUTCFullYear();
    let month = pad(date.getUTCMonth() + 1); // Months are zero-indexed
    let day = pad(date.getUTCDate());

    let hours = pad(date.getUTCHours());
    let minutes = pad(date.getUTCMinutes());
    let seconds = pad(date.getUTCSeconds());

    this.date = `${year}${month}${day}`;
    this.dateTime = `${year}${month}${day}T${hours}${minutes}${seconds}Z`;
  }
}


/**
 * Converts a string to a byte array.
 */
function encode(str: string): Uint8Array {
  let encoder: TextEncoder = new TextEncoder();
  return encoder.encode(str);
}


/**
 * Hashes the given payload using the SHA-256 algorithm into a hex-encoded string.
 */

async function getHash(payload: string | Uint8Array): Promise<string> {
  if (typeof payload == "string") {
    payload = encode(payload);
  }

  let hashBuffer = await crypto.subtle.digest('SHA-256', payload.buffer);
  let hashArray = new Uint8Array(hashBuffer);
  let hashHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}


type HeaderStrings = {
  canonicalHeaders: string;
  signedHeaders: string;
  canonicalQueryString: string;
};


function buildHeaderStrings(headers: Record<string, string>, queryParams: Record<string, string>): HeaderStrings {
    let canonicalHeaders = "";
    let signedHeaders = ""; 
    let headerKeys = Object.keys(headers).sort(); 
    for (let key of headerKeys) {
        canonicalHeaders += `${key.toLowerCase()}:${headers[key]}\n`;
        if (signedHeaders == "") {
            signedHeaders += key.toLowerCase();
        } else {
            signedHeaders += `;${key.toLowerCase()}`;
        }
    }

    let canonicalQueryArray = [];
    let paramKeys = Object.keys(queryParams).sort();
    for (let key of paramKeys) {
      canonicalQueryArray.push(`${key.toLowerCase()}=${queryParams[key]}`);
    }

    let canonicalQueryString = canonicalQueryArray.join("&");

    return {canonicalHeaders, signedHeaders, canonicalQueryString};
}


function getCanonicalRequest(httpVerb: string, canonicalUri: string, canonicalQueryString: string, canonicalHeaders: string, signedHeaders: string, unsignedPayloadHash: string): string {
    return [httpVerb, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, unsignedPayloadHash].join("\n");
}


async function getStringToSign(awsConfig: AWSConfig, canonicalRequest: string, now: AWSFormattedDate): Promise<string> {
  let hashedCanonicalRequest = await getHash(canonicalRequest);
  return (
    "AWS4-HMAC-SHA256\n" +
    `${now.dateTime}\n` +
    `${now.date}/${awsConfig.region}/${awsConfig.service}/aws4_request\n` +
    hashedCanonicalRequest
  );
}

async function createHmac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "HMAC", hash: "SHA-256"},
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
  return new Uint8Array(signature);
}


/**
 * 
 * @param {String} stringToSign - TODO: Come up with a better description.
 * @returns {String} TODO: Come up with a better description.
 */
async function getSignature(awsConfig: AWSConfig, stringToSign: string, now: AWSFormattedDate): Promise<string> {
  const sign = async (key: Uint8Array, msg: string): Promise<Uint8Array> => {
    return await createHmac(key, encode(msg));
  };

  const hexEncode = async (byteArray: Promise<Uint8Array>): Promise<string> => {
    return Array.from(await byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('')
  }

  const logHex = (byteArray: Uint8Array): string => {
    return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  const dateKey = await sign(encode(`AWS4${awsConfig.secretAccessKey}`), now.date);
  const dateRegionKey = await sign(dateKey, awsConfig.region);
  const dateRegionServiceKey = await sign(dateRegionKey, awsConfig.service);
  const signingKey = await sign(dateRegionServiceKey, "aws4_request");

  return hexEncode(sign(signingKey, stringToSign))
}


/**
 * 
 * @param {AWSConfig} awsConfig - The AWSConfig object.
 * @param {FormattedDate} now - The FormattedDate object.
 * @param {String} canonicalRequest - TODO: Come up with a better description
 * @param {String} signedHeaders - All headers included in the request.
 * @returns {String}
 */
async function getAuthorizationHeader(
  awsConfig: AWSConfig,
  now: AWSFormattedDate,
  canonicalRequest: string,
  signedHeaders: string
): Promise<string> {
  const stringToSign = await getStringToSign(awsConfig, canonicalRequest, now);
  const signature = await getSignature(awsConfig, stringToSign, now);

  return `AWS4-HMAC-SHA256 Credential=${awsConfig.accessKeyId}/${now.date}/${awsConfig.region}/${awsConfig.service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}


/**
 * 
 * @param {String} httpVerb - The desired HTTP verb action (i.e. GET, POST, DELETE, etc.).
 * @param {AWSConfig} awsConfig - The AWSConfig object.
 * @param {String} uriPath - The path to the desired AWS resource.
 * @param {Object} queryParams - TODO: Get a good definition of this.
 * @param {Object} headers - Any extra headers the AWS resource request may require.
 * @param {ArrayBuffer} payload - The body received from the HTTP request.
 * @returns {Promise<Response>} - The HTTP response from AWS.
 */
async function sendAwsHttpRequest(
  httpVerb: string,
  awsConfig: AWSConfig,
  uriPath: string,
  queryParams: Record<string, string>,
  headers: Record<string, string>,
  payload: Uint8Array
): Promise<Response> {
  let now = new AWSFormattedDate(new Date());

  if (uriPath == undefined) {
    uriPath = "/";
  } else if (!uriPath.startsWith("/")) {
    uriPath = "/" + uriPath;
  }

  let payloadHash = await getHash(payload);

  headers["host"] = awsConfig.host;
  headers["x-amz-date"] = now.dateTime;
  headers["x-amz-content-sha256"] = payloadHash
  // TODO: Make this match the payload length
  headers["content-length"] = String(payload.length);

  if (awsConfig.sessionToken) {
    headers["x-amz-security-token"] = awsConfig.sessionToken;
  }

  let { canonicalHeaders, signedHeaders, canonicalQueryString } = buildHeaderStrings(headers, queryParams);
  let canonicalRequest = getCanonicalRequest(
    httpVerb,
    uriPath,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  );

  headers["authorization"] = await getAuthorizationHeader(awsConfig, now, canonicalRequest, signedHeaders);

  delete headers["host"];

  let fetchOptions = {
    method: httpVerb,
    headers: headers,
    body: ["GET", "DELETE", "HEAD"].includes(httpVerb) ? undefined : payload
  };

  let response = await fetch(`http://${awsConfig.host}${uriPath}`, fetchOptions);
  
  return response;
}


export async function handler(request: Request, res: ResponseBuilder) {
  let awsConfig: AWSConfig = new AWSConfig();

  try {
    let payload: Uint8Array = encode(await request.text());
    let queryParams = {};
    let awsHeaders = {};
    let uriHeader = request.headers.get("uriPath");
    let uriPath: string = typeof uriHeader == 'string' ? uriHeader : "";
    let response: Response = await sendAwsHttpRequest(request.method, awsConfig, uriPath, queryParams, awsHeaders, payload);

    res.status(response.status);
    // TODO: Once Karthik fixes, update this to 'response.headers'
    res.set(response.headers);
    res.send(await response.arrayBuffer());
    
  } catch (error) {
    res.status(500);
    res.set({ 'Content-Type': 'text/plain' });
    res.send(`Error: ${error}\n`);
  }
}
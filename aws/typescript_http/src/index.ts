import { Variables, ResponseBuilder } from '@fermyon/spin-sdk';

class AWSConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
  service: string;
  host: string;

    constructor() {
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
 * Encodes a string to bytes using UTF-8 encoding
 */
function encode(str: string): Uint8Array {
  let encoder: TextEncoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * @returns A hex-encoded string of the byte array 
 */
async function hexEncode(byteArray: Uint8Array): Promise<string> {
  return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('')
}


/**
 * This creates a SHA256 hash of a string/byte array and returns a hex-encoded string
 */
async function getHash(payload: string | Uint8Array): Promise<string> {
  if (typeof payload == "string") {
    payload = encode(payload);
  }

  let hashBuffer = await crypto.subtle.digest('SHA-256', payload.buffer);
  let hashArray = new Uint8Array(hashBuffer);
  return hexEncode(hashArray);
}


type requestStrings = {
  canonicalHeaders: string;
  signedHeaders: string;
  canonicalQueryString: string;
};


function buildRequestStrings(headers: Record<string, string>, queryParams: Record<string, string>): requestStrings {
    // Formatted as header_key_1:header_value_1\nheader_key_2:header_value_2\n
    let canonicalHeaders = "";
    // Formatted as header_key_1;header_key_2
    let signedHeaders = ""; 
    // Header names must appear in alphabetical order
    let headerKeys = Object.keys(headers).sort(); 
    for (let key of headerKeys) {
        // Each header name must use lowercase characters
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


// The numbered functions below correspond to the image in the article linked here: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
// 1. Canonical Request
function getCanonicalRequest(httpVerb: string, canonicalUri: string, canonicalQueryString: string, canonicalHeaders: string, signedHeaders: string, payloadHash: string): string {
    return [httpVerb, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash].join("\n");
}


// 2. StringToSign
async function getStringToSign(config: AWSConfig, formattedDate: AWSFormattedDate, canonicalRequest: string): Promise<string> {
  let hashedCanonicalRequest = await getHash(canonicalRequest);
  let scope = [formattedDate.date, config.region, config.service, "aws4_request"].join("/")
  return ["AWS4-HMAC-SHA256", formattedDate.dateTime, scope, hashedCanonicalRequest].join("\n")
}


async function createHmac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  let cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "HMAC", hash: "SHA-256"},
    false,
    ["sign"]
  );

  let signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
  return new Uint8Array(signature);
}


// 3. Signature
async function getSignature(config: AWSConfig, formattedDate: AWSFormattedDate, stringToSign: string): Promise<string> {
  let sign = async (key: Uint8Array, msg: string): Promise<Uint8Array> => {
    return await createHmac(key, encode(msg));
  };

  let dateKey = await sign(encode(`AWS4${config.secretAccessKey}`), formattedDate.date);
  let dateRegionKey = await sign(dateKey, config.region);
  let dateRegionServiceKey = await sign(dateRegionKey, config.service);
  let signingKey = await sign(dateRegionServiceKey, "aws4_request");

  return hexEncode(await sign(signingKey, stringToSign))
}


async function getAuthorizationHeader(config: AWSConfig, formattedDate: AWSFormattedDate, canonicalRequest: string, signedHeaders: string): Promise<string> {
  let stringToSign = await getStringToSign(config, formattedDate, canonicalRequest);
  let signature = await getSignature(config, formattedDate, stringToSign);
  let credential = [config.accessKeyId, formattedDate.date, config.region, config.service, "aws4_request"].join("/");

  return `AWS4-HMAC-SHA256 Credential=${credential}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}


async function sendAwsHttpRequest(httpVerb: string, config: AWSConfig, uriPath: string, queryParams: Record<string, string>, headers: Record<string, string>, payload: Uint8Array): Promise<Response> {
  let formattedDate = new AWSFormattedDate(new Date());

  if (uriPath == undefined) {
    uriPath = "/";
  } else if (!uriPath.startsWith("/")) {
    uriPath = "/" + uriPath;
  }

  let payloadHash = await getHash(payload);

  // Keep in mind that these are the minimum headers required to interact with AWS. See the relevant service's API guide for any other required headers. 
  headers["host"] = config.host;
  headers["x-amz-date"] = formattedDate.dateTime;
  headers["x-amz-content-sha256"] = payloadHash
  headers["content-length"] = String(payload.length);
  // sessionToken is optional
  if (config.sessionToken) {
    headers["x-amz-security-token"] = config.sessionToken;
  }

  let { canonicalHeaders, signedHeaders, canonicalQueryString } = buildRequestStrings(headers, queryParams);
  let canonicalRequest = getCanonicalRequest(
    httpVerb,
    uriPath,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  );

  headers["authorization"] = await getAuthorizationHeader(config, formattedDate, canonicalRequest, signedHeaders);

  // Spin adds the host header on it's own, so we need to delete it here to avoid a duplicate header error
  delete headers["host"];

  let fetchOptions = {
    method: httpVerb,
    headers: headers,
    body: ["GET", "DELETE", "HEAD"].includes(httpVerb) ? undefined : payload
  };

  let response = await fetch(`http://${config.host}${uriPath}`, fetchOptions);
  
  return response;
}


export async function handler(request: Request, res: ResponseBuilder) {
  let config: AWSConfig = new AWSConfig();

  try {
    let payload: Uint8Array = encode(await request.text());
    // If necessary, add query parameters: 'query_params[key] = value'
    let queryParams = {};
    // If necessary, add extra headers: 'headers[key] = value'
    let awsHeaders = {};
    let uriHeader = request.headers.get("x-uri-path");
    let uriPath: string = typeof uriHeader == 'string' ? uriHeader : "";
    let response: Response = await sendAwsHttpRequest(request.method, config, uriPath, queryParams, awsHeaders, payload);

    res.status(response.status);
    res.set(response.headers);
    res.send(await response.arrayBuffer());
    
  } catch (error) {
    res.status(500);
    res.set({ 'Content-Type': 'text/plain' });
    res.send(`Error: ${error}\n`);
  }
}
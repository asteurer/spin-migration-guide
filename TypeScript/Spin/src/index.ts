// Convert to typescript

import { Config, HttpRequest, HttpResponse } from '@fermyon/spin-sdk';
// TODO: Change to the crypto module as seen here: 
import * as sha256 from "js-sha256";
import { TextEncoder } from 'util';
// import * as crypto from "crypto";


class AWSConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
  service: string;
  host: string;

    constructor() {
      // The class variables are initialized using the Spin variable retriever 'Config'.
      this.accessKeyId = Config.get("aws_access_key_id"); 
      this.secretAccessKey = Config.get("aws_secret_access_key");
      this.sessionToken = Config.get("aws_session_token");
      this.region = Config.get("aws_default_region");
      this.service = Config.get("aws_service");
      this.host = Config.get("aws_host");
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
function getHash(payload: string|Uint8Array): string {
  if (typeof payload == "string") {
    payload = encode(payload);
  }

  let hash = sha256.create()
  hash.update(payload);
  return hash.hex();
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


/**
 * TODO: Need a better overview for what StringToSign is.
 */
function getStringToSign(awsConfig: AWSConfig, canonicalRequest: string, now: AWSFormattedDate): string {
    return "AWS4-HMAC-SHA256\n" +
           `${now.dateTime}\n` +
           `${now.date}/${awsConfig.region}/${awsConfig.service}/aws4_request\n` +
           `${getHash(canonicalRequest)}`; 
}


/**
 * 
 * @param {String} stringToSign - TODO: Come up with a better description.
 * @returns {String} TODO: Come up with a better description.
 */
function getSignature(awsConfig: AWSConfig, stringToSign: string, now: AWSFormattedDate): string { 
  let sign = function(key: Uint8Array, msg: string): Uint8Array {
    let hmac = sha256.hmac.create(key);
    hmac.update(encode(msg));
    return hmac.arrayBuffer();
  }

  let dateKey: Uint8Array = sign(encode(`AWS4${awsConfig.secretAccessKey}`), now.date);
  let dateRegionKey: Uint8Array = sign(dateKey, awsConfig.region);
  let dateRegionServiceKey: Uint8Array = sign(dateRegionKey, awsConfig.service);
  let signingKey: Uint8Array = sign(dateRegionServiceKey, "aws4_request");

  let hmac = sha256.hmac.create(signingKey);
  hmac.update(encode(stringToSign));

  return hmac.hex();
}


/**
 * 
 * @param {AWSConfig} awsConfig - The AWSConfig object.
 * @param {FormattedDate} now - The FormattedDate object.
 * @param {String} canonicalRequest - TODO: Come up with a better description
 * @param {String} signedHeaders - All headers included in the request.
 * @returns {String}
 */
function getAuthorizationHeader(awsConfig: AWSConfig, now: AWSFormattedDate, canonicalRequest: string, signedHeaders: string) {
  let stringToSign: string = getStringToSign(awsConfig, canonicalRequest, now); 
  let signature: string = getSignature(awsConfig, stringToSign, now);

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
async function sendAwsHttpRequest(httpVerb: string, awsConfig: AWSConfig, uriPath: string, queryParams: Record<string, string>, headers: Record<string, string>, payload: Uint8Array ): HttpResponse {
  let now = new AWSFormattedDate(new Date());

  if (!["GET", "DELETE", "HEAD"].includes(httpVerb) && payload.length == 0) {
    throw new Error(`Please include a payload for request type: ${httpVerb}`);
  }
  
  if (uriPath == undefined) {
    uriPath = "/";
  } else if (!uriPath.startsWith("/")) {
    uriPath = "/" + uriPath;
  }

  headers["host"] = awsConfig.host;
  headers["x-amz-date"] = now.dateTime;
  headers["x-amz-content-sha256"] = getHash(payload);

  // TODO: Check that this doesn't appear as a blank string. 
  if (!awsConfig.sessionToken) {
    headers["x-amz-security-token"] = awsConfig.sessionToken;
  }

  let {canonicalHeaders, signedHeaders, canonicalQueryString} = buildHeaderStrings(headers, queryParams);
  let canonicalRequest = getCanonicalRequest(httpVerb, uriPath, canonicalQueryString, canonicalHeaders, signedHeaders, headers["x-amz-content-sha256"]);

  headers["authorization"] = getAuthorizationHeader(awsConfig, now, canonicalRequest, signedHeaders);
  
  // Spin adds a host header, so to avoid a duplicated header error, the host header used to sign the request needs to be deleted.
  delete headers["host"];

  let fetchOptions = {
    method: httpVerb,
    headers: headers,
    body: payload
  }

  return await fetch(`http://${awsConfig.host}${uriPath}`, fetchOptions);
}


export let handleRequest = async function (request: HttpRequest): HttpResponse {
  let awsConfig: AWSConfig = new AWSConfig();

  try {
    // TODO: Double check that .uriPath works, rather than headers["uriPath"]
    let queryParams = {};
    // TODO: Change let to let
    let awsHeaders = {};
    let response: HttpResponse = await sendAwsHttpRequest(request.method, awsConfig, request.headers.uriPath, queryParams, awsHeaders, request.body);   
    let body: string = await response.text();
    let headers: {[key: string]: string} = {};
    for (let [key, value] of response.headers.entries()) {
      headers[key] = value;
    }
    let status = response.status;
    
    return {
      status: status,
      headers: headers,
      body: body + "\n"
    };
  } catch (error) {
    return {
      status: 500,
      headers: {},
      body: `Error: ${error}\n`
    };
  }
};
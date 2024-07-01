import { ResponseBuilder, Variables } from "@fermyon/spin-sdk";
import { parse as urlParse } from "uri-js";

const utf8 = new TextEncoder();

class AZCredentials {
    private accountName: string;
    private accountKey: Uint8Array;

    public constructor(accountName: string, accountKey: string) {
        this.accountName = accountName;

        // Base64 decoding the account key and parsing that string into a byte array.
        const binaryString = atob(accountKey);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        this.accountKey = bytes;
    }

    public getAccountName(): string {
        return this.accountName;
    }

    public getAccountKey(): Uint8Array {
        return this.accountKey;
    }
}

export async function handler(request: Request, res: ResponseBuilder) {
    let accountName = Variables.get("az_account_name")!;
    let sharedKey = Variables.get("az_shared_key")!; 
    let endpoint = Variables.get("az_host")!;
    let url = urlParse(request.url);
    let uriPath = url.path!;
    let queryString = url.query!;
    
    if (queryString.length == 0) {
        if (uriPath == "/") {
            res.status(200);
            res.set({"content-type": "text/plain"});
            res.send("Error: If you are not including a query string, you must have a more specific URI path (i.e. /containerName/path/to/object)");
            return;
        } else {
            endpoint += uriPath; 
        }
    } else {
        endpoint += uriPath + "?" + queryString;
    }

    try {
      let body: Uint8Array = utf8.encode(await request.text());
      let response = await sendAzureRequest(request.method, endpoint, body, new Date(), accountName, sharedKey);
  
      res.status(response.status);
      res.set(response.headers);
      res.send(await response.arrayBuffer());
      
    } catch (error) {
      res.status(500);
      res.set({ 'Content-Type': 'text/plain' });
      res.send(`Error: ${error}\n`);
    }
  }

async function computeHMACSHA256(c: AZCredentials, message: Uint8Array): Promise<string> {
    let cryptoKey = await crypto.subtle.importKey("raw", c.getAccountKey(), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
    let signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
      // Convert ArrayBuffer to Uint8Array
      let signatureArray = new Uint8Array(signature);

      // Convert Uint8Array to binary string
      let binaryString = String.fromCharCode(...signatureArray);
    // Base64 encoding the signature
    return btoa(binaryString);
}

function buildStringToSign(c: AZCredentials, method: string, url: string, headers: {[key: string]: string}): string {
    let getHeader = function (key: string, headers: {[key: string]: string}): string {
        if (headers == undefined) {
            return "";
        }
        if (headers[key] != "") {
            return headers[key];
        }
        return "";
    }

    let contentLength = getHeader("Content-Length", headers);
    if (contentLength == "0") {
        contentLength = ""
    }

    let canonicalizedResource =  buildCanonicalizedResource(c, url);

    let stringToSign = [
        method,
        getHeader("Content-Encoding", headers),
        getHeader("Content-Language", headers),
        contentLength,
        getHeader("Content-MD5", headers),
        getHeader("Content-Type", headers),
        "", // Empty date because x-ms-date is expected
		getHeader("If-Modified-Since", headers),
		getHeader("If-Match", headers),
		getHeader("If-None-Match", headers),
		getHeader("If-Unmodified-Since", headers),
		getHeader("Range", headers),
		buildCanonicalizedHeader(headers),
		canonicalizedResource
    ].join("\n");

    console.log(`STRING TO SIGN:\n${stringToSign}`)

    return stringToSign
}

function buildCanonicalizedHeader(headers: {[key: string]: string}): string {
    let cm: {[key: string]: string} = {};
    for (let key of Object.keys(headers)) {
        let headerName = key.toLowerCase().trim();
        if (headerName.startsWith("x-ms-")) {
            cm[headerName] = headers[headerName];
        }
    }
    if (Object.keys(cm).length == 0) {
        return "";
    }

    let keys: string[] = []; 
    for (let key of Object.keys(cm)) {
        keys.push(key);
    }
    keys.sort();

    let ch = "";
    for (let i = 0; i < keys.length; i++) {
        if (i > 0) {
            ch += "\n";
        }

        ch += `${keys[i]}:${cm[keys[i]]}`;
    }
    
    return ch;
}

function buildCanonicalizedResource(c: AZCredentials, url: string): string {
    let u = urlParse(url);
    let cr = "/";
    cr += c.getAccountName();
    cr += u.path!;

    let makeParamMap = function(acc: {[key: string]: string}, entry: string): {[key: string]: string}{
        let [key, value]: string[] = entry.split("=");
        acc[key] = value;
        return acc;
    }
    
    let params = u.query!.split("&").reduce(makeParamMap, {});
    let paramNames: string[] = Object.keys(params)

    paramNames.sort();

    for (let paramName of paramNames) {
        let paramValue = params[paramName]
        cr += `\n${paramName.toLowerCase()}:${paramValue}`;
    }

    return cr;
}

async function sendAzureRequest(method: string, url: string, body: Uint8Array, now: Date, accountName: string, sharedKey: string): Promise<Response>{
    let cred = new AZCredentials(accountName, sharedKey);
    let headers: {[key: string]: string} = {};

    headers["x-ms-date"] = now.toUTCString();
    headers["x-ms-version"] = "2020-10-02";

    if (["PUT", "POST"].includes(method)) {
        headers["content-length"] = `${body.length}`
        headers["x-ms-blob-type"] = "BlockBlob";
    }

    let stringToSign = buildStringToSign(cred, method, url, headers);
    let signature = await computeHMACSHA256(cred, utf8.encode(stringToSign));
    let authHeader = `SharedKey ${accountName}:${signature}`;
    
    headers["authorization"] = authHeader;

    return await fetch(url, {method: method, headers: headers, body: ["GET", "DELETE", "HEAD"].includes(method) ? undefined : body});
}
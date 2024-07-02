import { ResponseBuilder, Variables } from "@fermyon/spin-sdk";
import { parse as urlParse } from "uri-js";

const utf8 = new TextEncoder();

class AZCredentials {
    private accountName: string;
    private accountKey: Uint8Array;
    private service: string;

    public constructor(accountName: string, accountKey: string, service: string) {
        this.accountName = accountName;
        this.service = service;

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

    public getService(): string {
        return this.service;
    }
}

export async function handler(request: Request, res: ResponseBuilder) {
    try {
        let accountName = Variables.get("az_account_name")!;
        let sharedKey = Variables.get("az_shared_key")!; 

        let service = request.headers.get("x-az-service");
        if (service == null) {
            res.status(200);
            res.set({"content-type": "text/plain"});
            res.send("Error: You must include the x-az-service in the request.");
            return;
        }

        let url = urlParse(request.url);
        let uriPath = url.path!;
        let queryString = url.query!;
        let queryParams: {[key: string]: string} = {};
        let endpoint = `https://${accountName}.${service}.core.windows.net`
        
        if (!queryString) {
            if (uriPath == "/") {
                res.status(200);
                res.set({"content-type": "text/plain"});
                res.send("Error: If you are not including a query string, you must have a more specific URI path (i.e. /containerName/path/to/object)");
                return;
            } else {
                endpoint += uriPath; 
            }
        } else {
            queryParams = parseQueryParams(queryString);
            let paramKeys = Object.keys(queryParams);
            let parsedQueryArray: string[] = [];
            for (let key of paramKeys) {
                parsedQueryArray.push(`${key}=${queryParams[key]}`);
            }

            endpoint += uriPath + "?" + parsedQueryArray.join("&");
        }

        try {
            let body: Uint8Array = utf8.encode(await request.text());
            let response = await sendAzureRequest(request.method, endpoint, queryParams, body, new Date(), accountName, sharedKey, service);
        
            res.status(response.status);
            res.set(response.headers);
            res.send(await response.arrayBuffer());
        
        } catch (error) {
            res.status(500);
            res.set({ 'content-type': 'text/plain' });
            res.send(`Error: ${error}\n`);
        }
    } catch(error) {
        res.status(500);
        res.set({ 'content-type': 'text/plain' });
        res.send(`Error: ${error}\n`);
    }
    
  }

  function parseQueryParams(queryString: string): {[key: string]: string} {
    let queryParams: {[key: string]: string} = {};
    let pairs = queryString.split("&");

    for (let pair of pairs) {
        // Handling cases where there is a "=" in the value portion of the param
        let [key, ...valueParts] = pair.split("=");
        let value = valueParts.join("=");

        queryParams[key] = (value || "");
    }

    return queryParams; 
}

async function computeHMACSHA256(c: AZCredentials, message: Uint8Array): Promise<string> {
    let cryptoKey = await crypto.subtle.importKey("raw", c.getAccountKey(), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
    let signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
    let signatureArray = new Uint8Array(signature);
    let binaryString = String.fromCharCode(...signatureArray);

    // Base64 encoding the signature
    return btoa(binaryString);
}

function buildStringToSign(c: AZCredentials, method: string, urlPath: string, headers: {[key: string]: string}, queryParams: {[key: string]: string}): string {
    // Returns a blank value if the header value doesn't exist
    let getHeader = function (key: string, headers: {[key: string]: string}): string {
        if (headers == undefined) {
            return "";
        }
        if (headers[key] != "") {
            return headers[key];
        }
        return "";
    }

    // Per the documentation, the Content-Length field must be an empty string if the content length of the request is zero.
    let contentLength = getHeader("content-length", headers);
    if (contentLength == "0") {
        contentLength = ""
    }

    let canonicalizedResource =  buildCanonicalizedResource(c, urlPath, queryParams);

    let stringToSign = [
        method,
        getHeader("content-encoding", headers),
        getHeader("content-language", headers),
        contentLength,
        getHeader("content-md5", headers),
        getHeader("content-type", headers),
        "", // Empty date because x-ms-date is expected
		getHeader("if-modified-since", headers),
		getHeader("if-match", headers),
		getHeader("if-none-match", headers),
		getHeader("if-unmodified-since", headers),
		getHeader("range", headers),
		buildCanonicalizedHeader(headers),
		canonicalizedResource
    ].join("\n");

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
    keys.sort(); // Canonicalized headers must be in lexicographical order

    let ch = "";
    for (let i = 0; i < keys.length; i++) {
        if (i > 0) {
            ch += "\n";
        }

        ch += `${keys[i]}:${cm[keys[i]]}`;
    }
    
    return ch;
}

function buildCanonicalizedResource(c: AZCredentials, urlPath: string, queryParams: {[key: string]: string}): string {
    let cr = "/" + c.getAccountName() + urlPath;

    let paramNames: string[] = Object.keys(queryParams)
    paramNames.sort();

    for (let paramName of paramNames) {
        let paramValue = queryParams[paramName]
        cr += `\n${paramName.toLowerCase()}:${paramValue}`;
    }

    return cr;
}

async function sendAzureRequest(method: string, url: string, queryParams: {[key: string]: string}, body: Uint8Array, now: Date, accountName: string, sharedKey: string, service: string): Promise<Response>{
    let cred = new AZCredentials(accountName, sharedKey, service);
    let headers: {[key: string]: string} = {};

    // Setting universally required headers
    headers["x-ms-date"] = now.toUTCString();
    headers["x-ms-version"] = "2024-08-04"; // Although not technically required, we strongly recommend specifying the latest Azure Storage API version: https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services

    // Setting method and service-specific headers
    if (["PUT", "POST"].includes(method)) {
        headers["content-length"] = `${body.length}`;

        if (service == "blob") {
            headers["x-ms-blob-type"] = "BlockBlob";
        }
    }

    let stringToSign = buildStringToSign(cred, method, urlParse(url).path!, headers, queryParams);
    let signature = await computeHMACSHA256(cred, utf8.encode(stringToSign));
    let authHeader = `SharedKey ${accountName}:${signature}`;
    
    headers["authorization"] = authHeader;

    return await fetch(url, {method: method, headers: headers, body: ["GET", "DELETE", "HEAD"].includes(method) ? undefined : body});
}
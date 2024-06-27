
import { ResponseBuilder, Variables } from "@fermyon/spin-sdk";
const { S3Client, ListObjectsV2Command, GetObjectCommand, DeleteObjectCommand, PutObjectCommand} = require("@aws-sdk/client-s3");

export async function handler(req: Request, res: ResponseBuilder) {

  let accessKeyId = Variables.get("aws_access_key_id");
  let secretAccessKey = Variables.get("aws_secret_access_key");
  let sessionToken = Variables.get("aws_session_token");
  let region = req.headers.get("x-aws-region");
  let bucketName = req.headers.get("x-s3-bucket");

  let credentials = {
    accessKeyId: accessKeyId,
    secretAccessKey: secretAccessKey,
    sessionToken: sessionToken
  }


    const client = new S3Client({
      region: region,
      credentials: credentials,
    });

    const params = {
        Bucket: bucketName
    };

    const command = new ListObjectsV2Command(params);
  
    let data

    try {
        data = await client.send(command);
        res.send(JSON.stringify(data.Contents, null, 2));
    } catch (e: any) {
        res.status(500)
        res.send(`error : ${e.message}`)
    }
}
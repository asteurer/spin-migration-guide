import json
import os
import boto3

def list_s3_objects(bucket_name: str) -> list:
    s3_client = boto3.client('s3')
    obj_dict = s3_client.list_objects_v2(Bucket=bucket_name)
    output = []

    for entry in obj_dict["Contents"]:
        output.append(entry["Key"]) # Adding the key names only
    
    return output

def lambda_handler(event, context):
    bucket_objects = list_s3_objects(os.environ['bucket_name'])

    return {
        'statusCode': 200,
        'body': json.dumps(bucket_objects)
    }
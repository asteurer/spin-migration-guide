# AWS Lambda to Spin Migration

## Purpose
This project demonstrates a migration path from AWS Lambda running Golang to Spin. The aim is to showcase the process and steps involved in moving serverless applications from AWS Lambda to a Spin environment.

## Prerequisites
- Because the image is being build directly in docker, there is no need to install dependencies.

## Setup

### Environment Variables
To streamline the build process, a `script.sh` file is provided. You will need to create a `.env` file in the same directory as `script.sh` and fill in the required environment variables:

```dotenv
DOCKERHUB_USER=your_dockerhub_username
DOCKERHUB_PASSWORD=your_dockerhub_password
IMAGE_TAG=your_image_tag
access_key_id=your_aws_access_key_id
secret_access_key=your_aws_secret_access_key
session_token=your_aws_session_token
bucket_name=your_s3_bucket_name

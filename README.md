## Overview

This is a guide for individuals who want to migrate their AWS Lambda functions to Web Assembly (Spin) applications. This guide assumes the user has familiarity with the following topics:

- AWS Lambda
- Making programmatic requests to AWS S3
- Making HTTP calls
- Golang, Python, or JavaScript
- Terraform
- Building an outgoing HTTP Spin application with environment variables


It's important to keep a few things in mind:

- Because the code will no longer be running within an AWS environment, the Spin application will need to have permissions to access the various AWS resources (i.e. updated S3 bucket policies, IAM roles, etc.)
- If the code uses environment variables, these will need to be added to the `spin.toml` file of your Spin application, and your code will need to migrate away from using the operating system environment variables to using the Spin SDK's `variables` library to access those variables. 
- If the Lambda function is exporting CloudWatch logs, this functionality will need to be manually added to the app or the platform.
- If the Lambda function relies on CloudWatch events, S3 bucket events, etc. the event generator will need to be redirected to have the Spin application as its endpoint.

## Spin and the AWS SDKs

As it currently stands, Spin does not support some of the libraries on which the Golang, Python, and JavaScript AWS SDKs rely. The current workaround is to make HTTP calls directly to the AWS API endpoints. This adds an extra layer of complexity, so here are a few points to consider when attempting this:

- Spin adds a `host` header to an outgoing HTTP request, so if the host header is not removed before the request is sent, there will be a header duplication error.
- It would be wise to pass the `host` as an environment variable into the`spin.toml` file, as well as into the Spin component. This ensures that the HTTP request signing process doesn't have any mismatches due to typos in the code.
- The API guides for each AWS service can be found here: https://docs.aws.amazon.com/. Navigate to the homepage of the desired service, then navigate to the API reference.

## Sources

- AWS article "Signing AWS API requests": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
- Github user asksac's AccessS3NoSDK repository: https://github.com/asksac/AccessS3NoSDK
- Github user joshuarose's spin-go-aws repository: https://github.com/joshuarose/spin-go-aws/
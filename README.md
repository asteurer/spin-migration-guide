title = "Migrating from AWS Lambda to Spin" template = "spin_main" date = "2024-05-24T00:00:01Z" enable_shortcodes = true [extra] url= "TODO: ADD THIS IN"
---
- [Content_Value_1]
- [Content_Value_2]

## Overview

This is a guide for individuals who want to migrate their AWS Lambda functions to Web Assembly (Spin) applications. This guide assumes the user has proficiency in the following topics:

- AWS Lambda
- Making programmatic requests to AWS S3
- Making REST/SOAP API calls
- Golang, Rust, Python, or JavaScript
- Terraform? TODO: Are we going to include terraform code in the migration guide?
- Building an outgoing HTTP Spin application with environment variables


It's important to keep a few things in mind:

- Because the code will no longer be running within an AWS environment, the Spin application will need to have permissions to access the various AWS resources (i.e. updated S3 bucket policies, IAM roles, etc.)
- If the code uses environment variables, these will need to be added to the `spin.toml` file of your Spin application, and your code will need to migrate away from using the operating system environment variables to using the Spin SDK's `variables` library to access those variables. 
- If the Lambda function is exporting CloudWatch logs, this functionality will need to be manually added to the application or runtime environment.
- If the Lambda function relies on CloudWatch events, S3 bucket events, etc. the event generator will need to be redirected to have the Spin application as its endpoint.

## Spin and the AWS SDKs

As it currently stands, Spin does not support some of the libraries on which the Golang, Python, JavaScript, and Rust AWS SDKs rely (TODO: VERIFY THIS). The current workaround is to make HTTP (TODO: Do we need to discuss HTTPS calls?) calls directly to the AWS API endpoints. This adds an extra layer of complexity, so here are a few points to consider when attempting this:

- Spin adds a `host` header to an outgoing HTTP request, so be sure not to add any host headers in the code to avoid header duplication errors.
- It would be wise to pass the `host` as an environment variable into the`spin.toml` file, as well as into the Spin component. This ensures that the HTTP request signing process doesn't have any mismatches due to typos in the code.
- The API guides for each AWS service can be found here: https://docs.aws.amazon.com/. Navigate to the homepage of the desired service, then navigate to the API reference.

## Example Code

{{ tabs "sdk-type" }}
{{ startTab "Python" }}

```python

```

{{ blockEnd }}
{{ startTab "Go" }}

```Golang
```

{{ blockEnd }}
{{ startTab "JavaScript" }}

```JavaScript
```

{{ blockEnd }}
{{ startTab "Rust"}}

```Rust
```

{{ blockEnd }}



## Sources

- AWS article "Authenticating Requests: Using Query Parameters": https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
- Github user asksac's AccessS3NoSDK repository: https://github.com/asksac/AccessS3NoSDK
- Github user joshuarose's spin-go-aws repository: https://github.com/joshuarose/spin-go-aws/
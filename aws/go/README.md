## Overview

At the moment, Spin does not have support for the AWS SDK. The current workaround is to make HTTP calls to the AWS service endpoints. This demonstrates how to effectively format and sign those HTTP requests.

## Requirements

- Latest version of Spin: https://developer.fermyon.com/spin/v2/install
- Go 1.22
- Tinygo 0.31
    - To install Tinygo, run the following commands: 
        ```bash
        wget https://github.com/tinygo-org/tinygo/releases/download/v0.31.2/tinygo_0.31.2_amd64.deb
        dpkg -i tinygo_0.31.2_amd64.deb
        export PATH=$PATH:/usr/local/bin

        ```

## Usage

This example will show how to interact with S3. See https://docs.aws.amazon.com for API information on other AWS services.

### Creating the .env file:

In the same directory as the code files, create a `.env` file with the below variables: 

```dotenv
SPIN_VARIABLE_AWS_ACCESS_KEY_ID=access-key-id
SPIN_VARIABLE_AWS_SECRET_ACCESS_KEY=secret-access-key
# Keep in mind, if your AWS account doesn't require MFA to access its resources, you may not need a session token. 
SPIN_VARIABLE_AWS_SESSION_TOKEN=session-token
# Example region
SPIN_VARIABLE_AWS_DEFAULT_REGION=us-west-2
# Example service
SPIN_VARIABLE_AWS_SERVICE=s3
# Note the port number at the end of the host
SPIN_VARIABLE_AWS_HOST=your-bucket-name.s3.us-west-2.amazonaws.com:80
```

Notice that the environment variables are formatted `SPIN_VARIABLE_UPPERCASE_VARIABLE_NAME`. This is the format required by Spin to read environment variables properly. As can be seen in the `spin.toml` file, the Spin application accesses the variables as `lowercase_variable_name`. 


### Building and running the application:

Once the .env is created, export the environment variables, build a virtual environment, install the dependencies, and then run the Spin application. 

Example commands for Debian Linux:

```bash
# Exporting the variables
set -a
source .env
set +a

# Installing dependencies
go mod download

# Building and running the Spin application
spin up --build
```


### Interacting with the application:

While the Spin app is running, open a new terminal window and try running the commands below:

#### List bucket objects:

```bash
curl http://127.0.0.1:3000
```

#### Get bucket object:

```bash
curl -o file_name.extension -H 'x-uri-path: s3/file/path' http://127.0.0.1:3000
```

#### Delete bucket object:

```bash
curl --request DELETE -H 'x-uri-path: s3/file/path' http://127.0.0.1:3000
```

#### Place object into bucket:

```bash
curl --request PUT -H 'x-uri-path: s3/file/path' --data-binary @/path/to/file http://127.0.0.1:3000
```

Documention of S3 actions: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
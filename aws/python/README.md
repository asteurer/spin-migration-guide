## Overview

At the moment, Spin does not have support for the AWS SDK. The current workaround is to make HTTP calls to the AWS service endpoints. This demonstrates how to effectively format and sign those HTTP requests.


## Requirements

- Latest version of Spin: https://developer.fermyon.com/spin/v2/install
- Python 3.12
- Python's `virtualenv` library installed: 
    - After Python is installed, run `pip install virtualenv` in the terminal.

## Usage

This example will show how to interact with S3. See https://docs.aws.amazon.com for API information for other AWS services.

### Creating the .env file:

In the same directory as the code files, create a `.env` file with the below variables: 

```dotenv
SPIN_VARIABLE_AWS_ACCESS_KEY_ID=access-key-id
SPIN_VARIABLE_AWS_SECRET_ACCESS_KEY=secret-access-key
# Keep in mind, if your AWS account doesn't require MFA to access its resources, you may not need a session token. 
SPIN_VARIABLE_AWS_SESSION_TOKEN=session-token
SPIN_VARIABLE_AWS_DEFAULT_REGION=us-west-2
SPIN_VARIABLE_AWS_SERVICE=s3
SPIN_VARIABLE_AWS_HOST=your-bucket-name.s3.us-west-2.amazonaws.com:443
```
Please take note of the following:

- The port number is included at the end of the `SPIN_VARIABLE_AWS_HOST` value. Spin adds the `Host` header to each outbound HTTP request, which does include the port number. If the port is not appended to the `SPIN_VARIABLE_AWS_HOST` variable, AWS will return a `SignatureDoesNotMatch` error. 

- The environment variables are formatted `SPIN_VARIABLE_UPPERCASE_VARIABLE_NAME`. This is the format required by Spin to read environment variables properly. As can be seen in the `spin.toml` file, the Spin application accesses the variables as `lowercase_variable_name`. 


### Building and running the application:

Once the .env is created, export the environment variables, build a virtual environment, install the dependencies, and then run the Spin application. 

Example commands for Debian Linux:

```bash
# Exporting the variables
set -a
source .env
set +a

# Creating and activating a virtual environment
python -m virtualenv venv
source venv/bin/activate

# Installing dependencies
pip install -r requirements.txt

# Building and running the Spin application
spin up --build

# Exit virtual environment
deactivate
```


### Interacting with the application:

While the Spin app is running, open a new terminal window and try running the commands below:

#### List bucket objects:

```bash
curl http://127.0.0.1:3000
```

#### Get bucket object:

```bash
curl -o file_name.extension http://127.0.0.1:3000/object/file/path
```

#### Delete bucket object:

```bash
curl --request DELETE http://127.0.0.1:3000/object/file/path
```

#### Place object into bucket:

```bash
curl --request PUT http://127.0.0.1:3000/object/file/path
```

Documention of S3 actions: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
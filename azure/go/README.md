## Overview

At the moment, Spin does not have support for the Azure SDK. The current workaround is to make HTTP calls to the Azure service endpoints. This demonstrates how to effectively format and sign those HTTP requests.

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

This example will show how to interact with Azure Blob Storage. See [Azure's documentation](https://learn.microsoft.com/en-us/rest/api/azure/) for API information on other Azure services.

### Creating the .env file:

In the same directory as the code files, create a `.env` file with the below variables: 

```dotenv
SPIN_VARIABLE_AZ_ACCOUNT_NAME="YOUR_ACCOUNT_NAME"
SPIN_VARIABLE_AZ_SHARED_KEY="YOUR_SHARED_KEY"
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

#### List blobs:

```bash
curl "http://127.0.0.1:3000/container-name?restype=container&comp=list"
```

#### Get blob:

```bash
curl -o file_name.extension "http://127.0.0.1:3000/container-name/path/to/your/blob"
```

#### Delete blob:

```bash
curl --request DELETE "http://127.0.0.1:3000/container-name/path/to/your/blob"
```

#### Place blob:

```bash
curl --request PUT --data-binary @/path/to/file "http://127.0.0.1:3000/container-name/path/to/your/blob"
```
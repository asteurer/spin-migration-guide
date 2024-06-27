## Overview

At the moment, Spin does not have support for the Azure SDK. The current workaround is to make HTTP calls to the Azure service endpoints. This demonstrates how to format and sign HTTP requests to Azure.

## Requirements

- Latest version of [Spin](https://developer.fermyon.com/spin/v2/install)
- Latest version of [Go](https://go.dev/doc/install)
- Latest version of [TinyGo](https://tinygo.org/getting-started/install/)


## Usage

This example will show how to interact with Azure Blob Storage. See Azure's [documentation](https://learn.microsoft.com/en-us/rest/api/azure/) for API information on other Azure services.

### Export environment variables

In your terminal, export the below variables:

```bash
export SPIN_VARIABLE_AZ_ACCOUNT_NAME=YOUR_ACCOUNT_NAME
export SPIN_VARIABLE_AZ_SHARED_KEY=YOUR_SHARED_KEY
```

Notice that the environment variables are formatted `SPIN_VARIABLE_UPPERCASE_VARIABLE_NAME`. This is the format required by Spin to read environment variables properly. As can be seen in the `spin.toml` file, the Spin application accesses the variables as `lowercase_variable_name`. 


### Building and running the application:

Navigate to the directory containing the codefiles, then run the below commands:

```bash
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
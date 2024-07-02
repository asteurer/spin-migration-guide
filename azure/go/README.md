## Overview

At the moment, Spin does not have support for the Azure SDK. The current workaround is to make HTTP calls to the Azure service endpoints. This demonstrates how to format and sign HTTP requests to Azure.

## Requirements

- Latest version of [Spin](https://developer.fermyon.com/spin/v2/install)
- Latest version of [Go](https://go.dev/doc/install)
- Latest version of [TinyGo](https://tinygo.org/getting-started/install/)


## Usage

This example will show how to interact with Azure Blob Storage and Azure Queue Storage. See Azure's [documentation](https://learn.microsoft.com/en-us/rest/api/azure/) for API information on other Azure services. 

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
curl \
    -H 'x-az-service: blob' \
    "http://127.0.0.1:3000/container-name?restype=container&comp=list"
```

#### Get blob:

```bash
curl \
    -o file_name.extension \
    -H 'x-az-service: blob' \
    http://127.0.0.1:3000/container-name/path/to/your/blob
```

#### Delete blob:

```bash
curl \
    --request DELETE \
    -H 'x-az-service: blob' \
    http://127.0.0.1:3000/container-name/path/to/your/blob
```

#### Place blob:

```bash
curl \
    --request PUT \
    -H 'x-az-service: blob' \
    --data-binary @/path/to/file \
    http://127.0.0.1:3000/container-name/path/to/your/blob
```

#### List queues:

```bash
curl \
    -H 'x-az-service: queue' \
    "http://127.0.0.1:3000?comp=list"
```
#### Get queue messages:

```bash
curl \
    -H 'x-az-service: queue' \
    http://127.0.0.1:3000/your-queue-name/messages
```

#### Delete queue message:

```bash
# The message-id and pop-receipt string values can be retrieved via getting messages from the queue.
curl \
    --request DELETE \
    -H 'x-az-service: queue' \
    "http://127.0.0.1:3000/your-queue-name/messages/your-message-id?popreceipt=your-pop-receipt-value"
```

#### Place queue message: 

```bash
# Per their documentation, the request body needs to be formatted using the XML as follows:
# <QueueMessage>
#   <MessageText>YourMessageHere</MessageText>
# </QueueMessage>
curl \
    --request POST \
    -H 'x-az-service: queue' \
    --data-binary @path/to/your/xml/message \
    http://127.0.0.1:3000/your-queue-name/messages
```
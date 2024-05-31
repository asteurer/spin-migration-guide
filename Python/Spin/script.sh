#!/bin/bash
set -a
source ../../.env
set +a

# Creating and activating a virtual environment
python -m virtualenv venv
source venv/bin/activate

# Installing dependencies
pip install -r requirements.txt

# Building and running the Spin application
spin up --build
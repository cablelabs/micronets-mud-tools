# Use an official Python runtime as a parent image
FROM python:3.6-slim

# Set the working directory to /app
WORKDIR /app

COPY bin/mudManager.py requirements.txt /app/
COPY bin/mudManager.py requirements.txt micronets-root-ca-2020.cert.pem /app/

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

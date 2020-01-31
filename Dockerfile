# Use an official Python runtime as a parent image
FROM python:3.6-slim

# Set the working directory to /app
WORKDIR /app

COPY bin/mudManager.py requirements.txt /app/
COPY bin/mudManager.py requirements.txt micronets-root-ca-2020.cert.pem /app/

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 8888 available to the world outside the container
EXPOSE 8888

# Run app.py when the container launches
CMD ["python", "mudManager.py", "-a", "0.0.0.0", "-p", "8888", "-cd", "/mud-cache-dir", \
     "-cac", "micronets-root-ca-2020.cert.pem", "--controller", "mm-api.micronets.in"]

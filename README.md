# Micronets Manufacturer Usage Description (MUD) Tools

This repository is for managing tools and data related to the use of MUD within the 
Micronets project.

## 1 Quick Start

### 1.1 Running the MUD Manager manually

From the micronets-mud-tools directory, perform the following steps:

Setup the virtualenv:
```
bin/setup-virtualenv.sh
```

Start the MUD manger:
```
virtualenv/bin/python bin/mudWS.py
```
(or if you plan to run the MUD Manager repeatedly, for debug/development)
```
source virtualenv/bin/activate
python bin/mudWS.py
```

You should see output similar to the following:
```
12/Dec/2018:22:53:57] ENGINE Bus STARTING
CherryPy Checker:
The Application mounted at '' has an empty config.

[12/Dec/2018:22:53:57] ENGINE Started monitor thread 'Autoreloader'.
[12/Dec/2018:22:53:57] ENGINE Serving on http://0.0.0.0:8888
[12/Dec/2018:22:53:57] ENGINE Bus STARTED
```

The MUD Manager can be stopped via Control-C. But it will also be stopped if/when the terminal session 
the proxy is started from terminates. The MUD Manager can also be run via systemd or Docker (see below).

### 1.2 Running the MUD Manager using systemd

From the micronets-mud-tools directory, perform the following steps to setup the virtualenv:

Setup the virtualenv:
```
bin/setup-virtualenv.sh
```

An example systemd service control file `micronets-mud-manager.service` is provided in the source 
distribution. The "WorkingDirectory" and "ExecStart" entries need to be modified to match the
location of the MUD Manager virtualenv and python code. And the "User" and "Group" settings
should be set to the "micronets" user (or commented out to run as "root") E.g.

```
WorkingDirectory=/home/micronets-dev/Projects/micronets/micronets-mud-tools
ExecStart=/home/micronets-dev/Projects/micronets/micronets-mud-tools/virtualenv/bin/python bin/websocket-proxy.py
User=micronets-dev
Group=micronets-dev
```

The systemctl service unit file can be installed for the systemd service using:

```
sudo systemctl enable $PWD/micronets-mud-manager.service
sudo systemctl daemon-reload
```

Once the micronets-mud-manager service is installed, it can be started using:

```
sudo systemctl start micronets-mud-manager.service
```

Where the logging will be written is system-dependent. On Ubuntu 16.04 systems
logging will be written to `/var/log/syslog`.

The status of the manager can be checked using:

```
sudo systemctl status micronets-mud-manager.service
```

and the manager can be stopped using:

```
sudo systemctl stop micronets-mud-manager.service
```

### 1.3 Running the MUD Manager using Docker

The MUD Manager distro includes a Dockerfile that can be used to construct
Docker images.

To build the Docker image:

```
docker build --tag=micronets-mud-manager .
```

To start a container locally and run it in the background:

```
docker run -d --network host --restart unless-stopped --name micronets-mud-manager-service micronets-mud-manager 
```

If running On MacOS (e.g. for testing):
```
docker run -d -p 8888:8888 --name micronets-mud-manager micronets-mud-manager
```

To stop the docker container:

```
docker kill micronets-mud-manager
```

### 1.4 Deploying a Docker image to Artifactory

A `Makefile` is provided to generate the Docker image and upload it to the configured artifact repository. 

Both can be accomplished by running:

```make docker-push```

Note that the destination repository and path is configured in the `Makefile` and that Docker will request 
credentials in order to perform the push.

### 1.5 Retrieving the latest docker image from Artifactory

The commands to retrieve the latest Docker image(s) for the MUD tools are also contained in the included Makefile. 

To pull the latest Docker(s) run:

```make docker-pull```

Note that the source repository and path is configured in the `Makefile`.
No credential should be required to pull the Docker image.

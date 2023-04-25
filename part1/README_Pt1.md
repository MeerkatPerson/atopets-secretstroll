
# README Pt. 1: Attribute-based credentials

## Setting up the environment

At this point, it is assumed that the virtual machine that was provided for completion of the project has been set up and a connection via ssh is enabled as instructed in the project README.

Start virtual machine. Log into the `root` account (username = `root`, passwort = `root`). Add `student` to the list of sudoers so Docker can be started from that account:

```
sudo usermod -a -G sudo student
```

Log out of `root` and into `student`.
Copy the entire directory `part1` to the virtual machine and connect to the machine via `ssh`:

```
scp -r -P 2222 part1 student@127.0.0.1:/home/student/part1 
ssh -p 2222 student@127.0.0.1
```
Switch to the directory `part1`. Change permissions of the `tor` directory. Start docker. 

```
cd part1
sudo chmod 777 tor
sudo rm /var/run/docker.pid
sudo systemctl stop docker
sudo dockerd
```
Next, in another window or using another `screen` if using the `screen` utility build the Docker images and start the containers:

```
sudo docker-compose build
sudo docker-compose up -d
```

## Running the issuance protocol

Connect to the `server` container. Set the `server` up to generate a keypair. Let the `server` run to wait for requests.

```
sudo docker exec -it cs523-server /bin/bash
cd server
python3 server.py setup -S restaurant -S bar -S sushi
python3 server.py run
```

Detach from the screen or use another terminal window. Connect to the `client` container. Obtain the server's public key and register to use the service.

```
sudo docker exec -it cs523-client /bin/bash
cd client
python3 client.py get-pk
python3 client.py register -u your_name -S restaurant -S bar
```

## Running the showing protocol (i.e., making location requests)

In the `client`-container's terminal, make a POI request for a geographical location in the Lausanne area:

```
python3 client.py loc 46.52345 6.57890 -T restaurant -T bar
```

## Running tests

Tests of the three atomic components of the protocol (`keygen`, `sign`, `verify`) as well as the issuance and showing phases of the protocol are available. Run them with the following commands:

```
python3 -m pytest credential_test.py
python3 -m pytest protocol_test.py
```

## Running evaluation of computation and communication cost

Computation cost of key generation, issuance, showing, and verification is measured in the form of computation time. Run the experiments with:

```
python3 benchmark_computation.py
```

Ordinarily, the script will also generate plots. This requires the libraries `pandas` and `seaborn`. Currently, the parts of the code that do this are commented out so that benchmarking the computation doesn't require having these two libraries installed (see bottom part of `benchmark_computation.py`). 

Communication cost of the issuance and showing phases is measured in the form of number and size (bytes) of packets. Note that for the experiments to work, `tshark` has to be installed in the client container. For `tshark` to work correctly in the client container, the `docker-compose.yaml` has to be adapted in the following manner:

```
client:
    ...
    cap_add:
      - ALL
```

To run the communication benchmark experiments, execute the following command:

```
python3 benchmark_communication.py
```
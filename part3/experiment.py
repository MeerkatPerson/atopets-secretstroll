from ipaddress import ip_address
import socket
import subprocess
import re
import os
import signal
import json

'''
IMPORTANT NOTE-s!!!!!!!

Had to adapt docker-compose.yaml and add the following under client container:

...
client:
...
    cap_add:
    - ALL
...

Otherwise, the client container has insufficient permissions to record packets using tshark.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For reference: problems when attempting to write pcap files with tshark may occur (permission denied, etc);
if that happens, check out the references below.

See https://www.techlanda.com/2020/02/tshark-file-to-which-capture-would-be.html and
https://www.linuxquestions.org/questions/linux-networking-3/tshark-gives-permission-denied-writing-to-any-file-in-home-dir-650952/

'''

'''
CURRENT PLAN:
- for each query (e.g. one request for POIs in one of the 100 grid cells 1-100), record a pcap and store that + the same data separated in to
  incoming and outgoing.
- I.e., for run 0, cell 1 we will store:
    * capture/cell_1/traffic_cell1_run0.pcap,
    * capture/cell_1/traffic_cell1_run0_incoming.pcap,
    * capture/cell_1/traffic_cell1_run0_outgoing.pcap
- But also, compute statistics using wireshark's capinfos utility, because we will need meta-data for the 100 different queries in order to be
    able to fingerprint the different queries.
- I.e., we will get a jsonarray with individual queries as datapoints, their meta-data as features. Ideally, we can use that already to run the
    classifier.
- If we need to change that plan, fall back to the pcap files.
'''


# Create directories for storing pcap files (if it doesn't alredy exist)
curr_dir = os.path.abspath(os.path.dirname(__file__))

capture_path = os.path.join(curr_dir, 'capture')

if not os.path.exists(capture_path):

    os.makedirs(capture_path)

# Find the current IP address
# we will need it later to compute statistics for incoming (ip.src != own_ip)and outgoing (ip.src == own_ip) packets separately
h_name = socket.gethostname()
ip_address = socket.gethostbyname(h_name)
print(f'Host IP Address: {ip_address}')

# below function is for getting the output of capinfos (tshark utility for computing statistics of a pcap file) as dict
# For info about capinfos please refer to https://www.wireshark.org/docs/man-pages/capinfos.html
# Code of below function is from https://gist.github.com/pocc/2c89dd92d6a64abca3db2a29a11f1404
# I don't really understand it, but it seems to do the job


def get_capinfos(filenames):
    """Get a dict from a packet using Wireshark's capinfos.
        Args:
            filenames (list): List of full filepaths to get info for
        Returns:
            (dict) of info about files
                {
                    "/path/to/file1": {"key": "value", ...},
                    ...
                }
        """
    cmd_list = ["capinfos", "-M"] + filenames

    try:
        output = subprocess.check_output(cmd_list).decode('utf-8')

    except:
        print('pcap file damaged!')

        # Try to repair damaged file

        cmd_list_ = ["pcapfix", "-d"] + filenames

        ex1 = subprocess.Popen(
            cmd_list_, close_fds=True
        ).wait()

        if ex1 < 0:

            print('Repair of pcap unsuccessful!')

            return dict()

        else:

            try:

                # filenames is a list for some reason atm, but it only has one element
                # according to documentation of pcapfix, the output file will be 'input file prepended by "fixed_".'
                fixed_filename = "fixed_" + filenames[0]

                cmd_list__ = ["capinfos", "-M"] + [fixed_filename]

                output = subprocess.check_output(cmd_list__).decode('utf-8')

            except:

                print(
                    'Error occurred when attempting to calculate infos on repaired file!')

                return dict()

    data = re.findall(r'(.+?):\s*([\s\S]+?)(?=\n[\S]|$)', output)
    infos_dict = {i[0]: i[1] for i in data}
    for key in infos_dict:
        if 'Interface #' in key:
            iface_infos = re.findall(r'\s*(.+?) = (.+)\n', infos_dict[key])
            infos_dict[key] = {i[0]: i[1] for i in iface_infos}

    return infos_dict


# Jsonarray which will store our data
# (not yet, experiment is currently just set up for one query to test)
data = []

fail_count = 0

for i in range(1, 101):
    cell_capture_path = os.path.join(capture_path, f'cell_{i}')

    if not os.path.exists(cell_capture_path):

        os.makedirs(cell_capture_path)

    # 200 runs per cell
    for j in range(100):

        overall_capture_path = os.path.join(
            cell_capture_path, f'traffic_cell{i}_run{j}.pcap')

        incoming_capture_path = os.path.join(
            cell_capture_path, f'traffic_cell{i}_run{j}_incoming.pcap')

        outgoing_capture_path = os.path.join(
            cell_capture_path, f'traffic_cell{i}_run{j}_outgoing.pcap')

        # Start recording using tcpdump
        # subprocess.Popen
        p1 = subprocess.Popen(
            ['tshark', '-i', 'eth0', '-w', overall_capture_path],  preexec_fn=os.setsid, close_fds=True)

        # Make query
        p2 = subprocess.Popen(
            ['python3', 'client.py', 'grid', str(i), '-T', 'restaurant', '-t'], close_fds=True
        ).wait()

        # Kill the recording
        os.killpg(os.getpgid(p1.pid), signal.SIGTERM)

        # Write the ingoing- and outgoing-only files (so statistics can be computed for those separately)
        status_in = subprocess.call(
            ["tshark", "-r", overall_capture_path, "-w", incoming_capture_path, "-Y", f"!(ip.src == {ip_address})"])

        status_out = subprocess.call(
            ["tshark", "-r", overall_capture_path, "-w", outgoing_capture_path, "-Y", f"ip.src == {ip_address}"])

        # Make dictionary for storing data
        # add nr. of queried cell
        data_dict = {'cell': i}

        # get statistics for complete packet capture (incoming & outgoing)
        total = get_capinfos([
            overall_capture_path])

        if not total:

            print('Repair of overall pcap unsuccessful!')

            fail_count += 1

            print(f'Fail count: {fail_count}')

            continue

        data_dict.update({'overall': total})

        # get statistics for incoming packets only
        incoming = get_capinfos([
            incoming_capture_path])

        if not incoming:

            print('Repair of incoming pcap unsuccessful!')

            fail_count += 1

            print(f'Fail count: {fail_count}')

            continue

        # print(incoming)

        data_dict.update({'incoming': incoming})

        # get statistics for outgoing packets only
        outgoing = get_capinfos([
            outgoing_capture_path])

        if not outgoing:

            print('Repair of outgoing pcap unsuccessful!')

            fail_count += 1

            print(f'Fail count: {fail_count}')

            continue

        data_dict.update({'outgoing': outgoing})

        unnested_data_dict = dict()

        # Un-nest data dict so it will be easier to process later on when we will most likely transform it into a numpy array or something
        for key, value in data_dict.items():

            if key == 'cell':

                unnested_data_dict.update({key: value})

            else:

                for nested_key, nested_value in value.items():

                    unnested_data_dict.update(
                        {key + '_' + nested_key: nested_value})

        data.append(unnested_data_dict)

with open("results.json", "w") as outfile:
    json.dump(data, outfile)

print(f'Fails: {fail_count} / 250')

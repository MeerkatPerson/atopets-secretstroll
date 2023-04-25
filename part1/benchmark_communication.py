
from ipaddress import ip_address
from math import sqrt
import socket
import subprocess
import os
import signal
import random
import statistics
from time import sleep

# Create directories for storing pcap files (if it doesn't alredy exist)
curr_dir = os.path.abspath(os.path.dirname(__file__))

capture_path = os.path.join(curr_dir, 'benchmark_communication')

if not os.path.exists(capture_path):

    os.makedirs(capture_path)

# Find the current IP address
# we will need it later to compute statistics for incoming (ip.src != own_ip)and outgoing (ip.src == own_ip) packets separately
h_name = socket.gethostname()
ip_address = socket.gethostbyname(h_name)
print(f'Host IP Address: {ip_address}')

num_packets_issuance_overall = []
num_packets_issuance_incoming = []
num_packets_issuance_outgoing = []

avg_packet_size_issuance_overall = []
avg_packet_size_issuance_incoming = []
avg_packet_size_issuance_outgoing = []

num_packets_showing_overall = []
num_packets_showing_incoming = []
num_packets_showing_outgoing = []

avg_packet_size_showing_overall = []
avg_packet_size_showing_incoming = []
avg_packet_size_showing_outgoing = []

for i in range(100):

    # Pt. 1: benchmark number of packets & avg packet size for issuance protocol

    # Remove credential if existent
    if os.path.exists("anon.cred"):
        os.remove("anon.cred")

    # NOTE we're assuming here the server has already been setup using the available
    #       subscriptions from the documentation (restaurant, bar, sushi)
    #       and the client has run 'get_pk'
    #       already so as to obtain the issuer's public key

    overall_issuance_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_issuance.pcap')

    incoming_issuance_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_issuance_incoming.pcap')

    outgoing_issuance_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_issuance_outgoing.pcap')

    print(overall_issuance_capture_path)

    # Start recording using tcpdump
    # subprocess.Popen
    p1 = subprocess.Popen(
        ['tshark', '-i', 'eth0', '-w', overall_issuance_capture_path],  preexec_fn=os.setsid, close_fds=True)

    sleep(5)

    # Send registration request
    subprocess.Popen(
        ['python3', 'client.py', 'register', '-u', 'your_name', '-S', 'restaurant', '-S', 'bar'], close_fds=True
    ).wait()

    sleep(15)

    # Stop the recording
    os.killpg(os.getpgid(p1.pid), signal.SIGTERM)

    # Write the ingoing- and outgoing-only files (so statistics can be computed for those separately)
    status_in = subprocess.call(
        ["tshark", "-r", overall_issuance_capture_path, "-w", incoming_issuance_capture_path, "-Y", f"!(ip.src == {ip_address})"])

    status_out = subprocess.call(
        ["tshark", "-r", overall_issuance_capture_path, "-w", outgoing_issuance_capture_path, "-Y", f"ip.src == {ip_address}"])

    # Calculate number of packets & avg packet size for overall capture
    '''
    try:
        
        num_packets_issuance_overall_elem = subprocess.check_output(
        ['capinfos', '-c', overall_issuance_capture_path])

    except:

        ["pcapfix", "-d", overall_issuance_capture_path]

        num_packets_issuance_overall_elem = subprocess.check_output(
        ['capinfos', '-c', overall_issuance_capture_path])

    '''

   #  num_packets_issuance_overall.append(int(num_packets_issuance_overall_elem))

    '''
    avg_packet_size_issuance_overall_elem = subprocess.check_output(
        ['capinfos', '-z', overall_issuance_capture_path])
    avg_packet_size_issuance_overall.append(
        int(avg_packet_size_issuance_overall_elem))

    '''

    # Calculate number of packets & avg packet size for incoming only capture
    num_packets_issuance_incoming_output = subprocess.check_output(
        ['capinfos', '-c', incoming_issuance_capture_path])
    
    num_packets_issuance_incoming_output_list = num_packets_issuance_incoming_output.split()
    num_packets_issuance_incoming_elem = int((num_packets_issuance_incoming_output_list[len(num_packets_issuance_incoming_output_list) - 1]).decode('utf-8'))

    print(f'[Issuance] Num packets incoming: {num_packets_issuance_incoming_elem}')

    num_packets_issuance_incoming.append(
        num_packets_issuance_incoming_elem)

    avg_packet_size_issuance_incoming_output = subprocess.check_output(
        ['capinfos', '-z', incoming_issuance_capture_path])

    avg_packet_size_issuance_incoming_output_list = avg_packet_size_issuance_incoming_output.split()
    avg_packet_size_issuance_incoming_elem = float((avg_packet_size_issuance_incoming_output_list[len(avg_packet_size_issuance_incoming_output_list) - 2]).decode('utf-8'))

    print(f'[Issuance] Avg packet size incoming: {avg_packet_size_issuance_incoming_elem}')

    avg_packet_size_issuance_incoming.append(
        avg_packet_size_issuance_incoming_elem)

    # Calculate number of packets & avg packet size for outgoing only capture
    num_packets_issuance_outgoing_output = subprocess.check_output(
        ['capinfos', '-c', outgoing_issuance_capture_path])

    num_packets_issuance_outgoing_output_list = num_packets_issuance_outgoing_output.split()
    num_packets_issuance_outgoing_elem = int((num_packets_issuance_outgoing_output_list[len(num_packets_issuance_outgoing_output_list) - 1]).decode('utf-8'))

    print(f'[Issuance] Num packets outgoing: {num_packets_issuance_outgoing_elem}')

    num_packets_issuance_outgoing.append(
        num_packets_issuance_outgoing_elem)

    avg_packet_size_issuance_outgoing_output = subprocess.check_output(
        ['capinfos', '-z', outgoing_issuance_capture_path])

    avg_packet_size_issuance_outgoing_output_list = avg_packet_size_issuance_outgoing_output.split()
    avg_packet_size_issuance_outgoing_elem = float((avg_packet_size_issuance_outgoing_output_list[len(avg_packet_size_issuance_outgoing_output_list) - 2]).decode('utf-8'))

    print(f'[Issuance] Avg packet size outgoing: {avg_packet_size_issuance_outgoing_elem}')

    avg_packet_size_issuance_outgoing.append(
        avg_packet_size_issuance_outgoing_elem)

    # --------------------------------------------------------------------------------

    # Pt. 2: benchmark number of packets & avg packet size for issuance protocol

    overall_showing_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_showing.pcap')

    incoming_showing_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_showing_incoming.pcap')

    outgoing_showing_capture_path = os.path.join(
        capture_path, f'traffic_run{i}_showing_outgoing.pcap')

    # Calculate a random location to query POIs for
    lat = round(random.uniform(46.5, 46.57),2)
    lon = round(random.uniform(6.55, 6.65),2)

    # Start recording using tcpdump
    # subprocess.Popen
    p3 = subprocess.Popen(
        ['tshark', '-i', 'eth0', '-w', overall_showing_capture_path],  preexec_fn=os.setsid, close_fds=True)

    sleep(5)

    # Send a location query
    p4 = subprocess.Popen(
        ['python3', 'client.py', 'loc', str(lat), str(lon), '-T', 'restaurant', '-T', 'bar'], close_fds=True
    ).wait()

    sleep(15)

    # Stop the recording
    os.killpg(os.getpgid(p3.pid), signal.SIGTERM)

    # Write the ingoing- and outgoing-only files (so statistics can be computed for those separately)
    status_in = subprocess.call(
        ["tshark", "-r", overall_showing_capture_path, "-w", incoming_showing_capture_path, "-Y", f"!(ip.src == {ip_address})"])

    status_out = subprocess.call(
        ["tshark", "-r", overall_showing_capture_path, "-w", outgoing_showing_capture_path, "-Y", f"ip.src == {ip_address}"])

    # Calculate number of packets & avg packet size for overall capture
    '''
    num_packets_showing_overall_elem = subprocess.check_output(
        ['capinfos', '-c', overall_showing_capture_path])
    num_packets_showing_overall.append(int(num_packets_showing_overall_elem))

    avg_packet_size_showing_overall_elem = subprocess.check_output(
        ['capinfos', '-z', overall_showing_capture_path])
    avg_packet_size_showing_overall.append(
        int(avg_packet_size_showing_overall_elem))
    '''

    # Calculate number of packets & avg packet size for incoming only capture
    num_packets_showing_incoming_output = subprocess.check_output(
        ['capinfos', '-c', incoming_showing_capture_path])

    num_packets_showing_incoming_output_list = num_packets_showing_incoming_output.split()
    num_packets_showing_incoming_elem = int((num_packets_showing_incoming_output_list[len(num_packets_showing_incoming_output_list) - 1]).decode('utf-8'))

    print(f'[Showing] Num packets incoming: {num_packets_showing_incoming_elem}')

    num_packets_showing_incoming.append(
        num_packets_showing_incoming_elem)

    avg_packet_size_showing_incoming_output = subprocess.check_output(
        ['capinfos', '-z', incoming_showing_capture_path])

    avg_packet_size_showing_incoming_output_list = avg_packet_size_showing_incoming_output.split()
    avg_packet_size_showing_incoming_elem = float((avg_packet_size_showing_incoming_output_list[len(avg_packet_size_showing_incoming_output_list) - 2]).decode('utf-8'))

    print(f'[Showing] Avg packet size incoming: {avg_packet_size_showing_incoming_elem}')

    avg_packet_size_showing_incoming.append(
        avg_packet_size_showing_incoming_elem)

    # Calculate number of packets & avg packet size for outgoing only capture
    num_packets_showing_outgoing_output = subprocess.check_output(
        ['capinfos', '-c', outgoing_showing_capture_path])

    num_packets_showing_outgoing_output_list = num_packets_showing_outgoing_output.split()
    num_packets_showing_outgoing_elem = int((num_packets_showing_outgoing_output_list[len(num_packets_showing_outgoing_output_list) - 1]).decode('utf-8'))

    print(f'[Showing] Num packets outgoing: {num_packets_showing_outgoing_elem}')

    num_packets_showing_outgoing.append(
        num_packets_showing_outgoing_elem)

    avg_packet_size_showing_outgoing_output = subprocess.check_output(
        ['capinfos', '-z', outgoing_showing_capture_path])

    avg_packet_size_showing_outgoing_output_list = avg_packet_size_showing_outgoing_output.split()
    avg_packet_size_showing_outgoing_elem = float((avg_packet_size_showing_outgoing_output_list[len(avg_packet_size_showing_outgoing_output_list) - 2]).decode('utf-8'))

    print(f'[Showing] Avg packet size outgoing: {avg_packet_size_showing_outgoing_elem}')

    avg_packet_size_showing_outgoing.append(
        avg_packet_size_showing_outgoing_elem)

    # ------------------------------------------------------------------------------------------------------

# Num Packets, Packet Size ISSUANCE OVERALL
# print(f'[Issuance Overall Num Packets] Mean (100 runs): {statistics.mean(num_packets_issuance_overall)}, SE: {statistics.stdev(num_packets_issuance_overall)/sqrt(100)}')
# print(f'[Issuance Overall Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_issuance_overall)}, SE: {statistics.stdev(avg_packet_size_issuance_overall)/sqrt(100)}')

# Num Packets, Packet Size ISSUANCE INCOMING
print(f'[Issuance Incoming Num Packets] Mean (100 runs): {statistics.mean(num_packets_issuance_incoming)}, SE: {statistics.stdev(num_packets_issuance_incoming)/sqrt(100)}')
print(f'[Issuance Incoming Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_issuance_incoming)}, SE: {statistics.stdev(avg_packet_size_issuance_incoming)/sqrt(100)}')

# Num Packets, Packet Size ISSUANCE OUTGOING
print(f'[Issuance Outgoing Num Packets] Mean (100 runs): {statistics.mean(num_packets_issuance_outgoing)}, SE: {statistics.stdev(num_packets_issuance_outgoing)/sqrt(100)}')
print(f'[Issuance Outgoing Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_issuance_outgoing)}, SE: {statistics.stdev(avg_packet_size_issuance_outgoing)/sqrt(100)}')

# Num Packets, Packet Size SHOWING OVERALL
# print(f'[Showing Overall Num Packets] Mean (100 runs): {statistics.mean(num_packets_showing_overall)}, SE: {statistics.stdev(num_packets_showing_overall)/sqrt(100)}')
# print(f'[Showing Overall Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_showing_overall)}, SE: {statistics.stdev(avg_packet_size_showing_overall)/sqrt(100)}')

# Num Packets, Packet Size SHOWING INCOMING
print(f'[Showing Incoming Num Packets] Mean (100 runs): {statistics.mean(num_packets_showing_incoming)}, SE: {statistics.stdev(num_packets_showing_incoming)/sqrt(100)}')
print(f'[Showing Incoming Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_showing_incoming)}, SE: {statistics.stdev(avg_packet_size_showing_incoming)/sqrt(100)}')

# Num Packets, Packet Size SHOWING OUTGOING
print(f'[Showing Outgoing Num Packets] Mean (100 runs): {statistics.mean(num_packets_showing_outgoing)}, SE: {statistics.stdev(num_packets_showing_outgoing)/sqrt(100)}')
print(f'[Showing Outgoing Avg Packet Size] Mean (100 runs): {statistics.mean(avg_packet_size_showing_outgoing)}, SE: {statistics.stdev(avg_packet_size_showing_outgoing)/sqrt(100)}')

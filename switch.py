#!/usr/bin/python3
import os
import struct
import sys
import threading
import time

import wrapper
from wrapper import get_interface_name, get_switch_mac, recv_from_any_link, send_to_link


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    # dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder="big")
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack("!H", 0x8200) + struct.pack("!H", vlan_id & 0x0FFF)


def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)


def main():
    # Closure to send a frame to a link with the VLAN tag if necessary
    def vlan_send_to_link(interface, length, data, vlan_id):
        interface_name = get_interface_name(interface)
        if interface_vlans[interface_name] == "T":
            # This is a trunk port. Send the frame with the VLAN tag
            print("HERE1")
            tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
            send_to_link(interface, length + 4, tagged_frame)
        elif interface_vlans[interface_names[i]] == str(vlan_id):
            # This is an access port. Send the frame without the VLAN tag if it has the same VLAN id
            print("HERE2")
            send_to_link(interface, length, data)
        else:
            # Drop the frame
            print("HERE3")
            print(f"Frame dropped on interface {interface_name}")

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ":".join(f"{b:02x}" for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    interface_names = []
    # Printing interface names
    for i in interfaces:
        interface_names.append(get_interface_name(i))
        print(get_interface_name(i))

    # Initialize the VLAN id for each interface
    config_file = os.path.join("configs", f"switch{switch_id}.cfg")
    interface_vlans = {}

    try:
        with open(config_file, "r") as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) == 2:
                    interface, vlan = parts
                    interface_vlans[interface] = vlan
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found.", flush=True)
        sys.exit(1)

    print(interface_vlans)

    # Initialize the CAM table
    # It's a dict with keys being the MAC addresses and values being the interface
    cam_table = {}

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ":".join(f"{b:02x}" for b in dest_mac)
        src_mac = ":".join(f"{b:02x}" for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f"Destination MAC: {dest_mac}")
        print(f"Source MAC: {src_mac}")
        print(f"EtherType: {ethertype}")
        if vlan_id == -1:
            if interface_vlans[get_interface_name(interface)] != "T":
                vlan_id = int(interface_vlans[get_interface_name(interface)])
        print(f"VLAN ID: {vlan_id}")

        print(
            "Received frame of size {} on interface {}".format(length, interface),
            flush=True,
        )

        # Add the source MAC to the CAM table
        cam_table[src_mac] = interface

        if dest_mac == "ff:ff:ff:ff:ff:ff" or dest_mac not in cam_table:
            # Broadcast MAC address or unknown MAC address
            for i in interfaces:
                if i != interface:
                    send_to_link(i, length, data)
                    # vlan_send_to_link(i, length, data, vlan_id)
        else:
            # If the destination MAC is in the CAM table, forward the frame
            send_to_link(cam_table[dest_mac], length, data)
            # vlan_send_to_link(cam_table[dest_mac], length, data, vlan_id)

        # for mac, interface in cam_table.items():
        #     print(f"MAC: {mac} -> Interface: {interface}")

        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)


if __name__ == "__main__":
    main()

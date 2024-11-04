#!/usr/bin/python3
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

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

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
        tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]

        print(f"Destination MAC: {dest_mac}")
        print(f"Source MAC: {src_mac}")
        print(f"EtherType: {ethertype}")
        print(f"VLAN ID: {vlan_id}")

        print(
            "Received frame of size {} on interface {}".format(length, interface),
            flush=True,
        )

        # Add the source MAC to the CAM table
        cam_table[src_mac] = interface

        if dest_mac == "ff:ff:ff:ff:ff:ff":
            # Broadcast MAC address
            for i in interfaces:
                if i != interface:
                    send_to_link(i, length, data)

        else:
            # If the destination MAC is in the CAM table, forward the frame
            if dest_mac in cam_table:
                send_to_link(cam_table[dest_mac], length, data)
            else:
                # The switch doesn't know where the destination MAC is
                # Flood the frame to all interfaces except the one it was received on
                for i in interfaces:
                    if i != interface:
                        send_to_link(i, length, data)

        # for mac, interface in cam_table.items():
        #     print(f"MAC: {mac} -> Interface: {interface}")

        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)


if __name__ == "__main__":
    main()

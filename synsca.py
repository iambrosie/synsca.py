#!/usr/bin/env python

__author__ = 'ambrozie'

import os
import sys
import argparse
import time
from socket import gethostbyname, gaierror
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
# don't resolve service names
conf.noenum.add(TCP.sport, TCP.dport)


def scan(target, ports):
    """
    Given a target, be it in the form of a hostname or an ip, and a destination
    TCP port, or a list a ports for that matter, check whether the respective
    port is open by using a technique known as SYN scan
    """
    # constructing the segment
    segment = IP(dst = target) / TCP(dport = ports, flags = 'S')
    # send segment and register the reply
    ans, unans = sr(segment, timeout = 0.1)
    # pretty print the reply
    ans.summary(
            # apply the filter function to each packet (i.e. decide whether 
            # it will be displayed or not)
            lfilter = lambda(s, r) : r.sprintf("%TCP.flags%") == "SA",
            # function to apply to each packet
            prn = lambda(s, r) : r.sprintf("%TCP.sport% is open"
                                           " (%TCP.flags%)")
            )


def isup(target):
    """
    Given a target, be it in the form of a hostname or an ip, returns a boolean
    value corresponding to whether the target replies to an ICMP ECHO request
    """
    up = False
    # construct an ICMP echo request datagram
    echo_datagram = IP(dst = target) / ICMP(type = 0x8)
    # send the echo request and wait for a reply
    res = sr1(echo_datagram, timeout = 1)
    # if the reply is indeed an echo reply, we can blissfully assume the 
    # host is up
    if not (res is None) and res.haslayer(ICMP):
        if res['ICMP'].type == 0x0:
            up = True
    return up


def _parse_args():
    """
    Parse the user-provided arguments, when the script is being used from the
    command line
    """
    parser = argparse.ArgumentParser(
            description = 'scapy-based TCP SYN scanner',
            formatter_class=argparse.RawTextHelpFormatter
            )
    parser.add_argument(
            '-p',
            dest = 'ports',
            help = "target ports with the input format being a\n"
                   "comma-separated list of ports and (or) port ranges\n"
                   "(e.g. 80,135-139,200)\n"
                   "the default value is 80\n"
                   "please note that space characters are not allowed",
            default = '80'
            )
    parser.add_argument(
            'target', 
            help='target IP address or hostname'
            )
    args = parser.parse_args()
    return args


def main(args):
    """
    This is the workhorse of the script. 
    Provided with the command line arguments, this function sets up the 
    parameters for the calls to the above-defined functions.
    It is also responsible for printing informative messages and timing the 
    scan.
    """
    # parse target
    target = args.target
    # check whether the target is valid
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print('the provided target is not a valid hostname / IP address')
        return
    # check whether the target is up
    if isup(target):
        print('%s is up' % target)
    else:
        print('%s seems down\nAbording' % target)
        return
    # parse target ports
    ranges = [x.split("-") for x in args.ports.replace(' ', '').split(",")]
    ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]
    # register scan start time
    start_time = time.time()
    print('started scanning')
    # scan every port in the range and print output
    scan(target, ports)
    # print footer 
    duration = time.time() - start_time
    print('scanning finished in %0.0f seconds' % duration)
  

if __name__ == '__main__':
    # check for the appropriate privilege level
    if os.geteuid() != 0:
        sys.exit("this script uses raw sockets so it needs root capabilities"
                 "\nplease rerun as root")
    args = _parse_args()
    main(args)

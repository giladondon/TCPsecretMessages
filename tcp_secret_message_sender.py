import sys
import random
i, e, o = sys.stdin, sys.stderr, sys.stdout
from scapy.all import *
sys.stdin, sys.stderr, sys.stdout = i, e, o

__author__ = 'Gilad Barak'
__name__ = 'main'

MAXIMUM_8_DIGITS = 10000000
SYN = 'S'
IP_RECEIVER = '172.16.1.29'


def input_from_user():
    """
    :return input: Message from user, division number
    """
    return raw_input("Please enter message: "), raw_input("Please enter division number: ")


def generate_syn(port):
    """
    :param port: for handshake to be initiated with
    :return : Syn packet
    """
    seq = random.choice(range(MAXIMUM_8_DIGITS))
    syn_segment = TCP(dport=port, seq=seq, flags=SYN)
    return IP(dst=IP_RECEIVER) / syn_segment


def generate_ack(port, seq, ack):
    """
    :param port: for handshake to be initiated with
    :return : Ack packet
    """
    ack_segment = TCP(dport=port, seq=seq, ack=ack)
    return IP(dst=IP_RECEIVER) / ack_segment


def initiate_three_way_handshake(port):
    """
    :param port: for handshake to be initiated with
    """
    syn_ack = sr1(generate_syn(port))

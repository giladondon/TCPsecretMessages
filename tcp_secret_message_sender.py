import sys
import random
i, e, o = sys.stdin, sys.stderr, sys.stdout
from scapy.all import *
sys.stdin, sys.stderr, sys.stdout = i, e, o

__author__ = 'Gilad Barak'
__name__ = 'main'

MAXIMUM_8_DIGITS = 10000000
SYN_FLAG = 'S'
ACK_FLAG = 'A'
IP_RECEIVER = '172.16.1.29'
ACK_PACKET_INDEX = 0
ACK_SEQ_INDEX = 1
SYN_SEQ_VALUE = 1
SEPARATOR = '~'


def input_from_user():
    """
    :return input: Message from user, division number
    """
    return raw_input("Please enter message: "), raw_input("Please enter division number: ")


def generate_syn(port):
    """
    :param port: for handshake to be initiated with
    :rtype : scapy.layers.inet.TCP
    :return : Syn packet, randomized sequence value
    """
    seq = random.choice(range(MAXIMUM_8_DIGITS))
    syn_segment = TCP(dport=port, seq=seq, flags=SYN_FLAG)
    return IP(dst=IP_RECEIVER) / syn_segment, seq


def generate_ack(port, seq_value, ack_value):
    """
    :param port: for acknowledgment to be initiated with
    :param seq_value: for acknowledgment to be initiated with
    :param ack_value: for acknowledgment to be initiated with
    :rtype : scapy.layers.inet.TCP
    :return : Ack packet
    """
    ack_segment = TCP(dport=port, seq=seq_value, ack=ack_value, flags=ACK_FLAG)
    return IP(dst=IP_RECEIVER) / ack_segment


def initiate_three_way_handshake(port):
    """
    :param port: for handshake to be initiated with
    :rtype : tuple
    :return : current acknowledgement value, current sequence value
    """
    syn_data = generate_syn(port)
    syn_ack_packet = sr1(syn_data[ACK_PACKET_INDEX])

    seq_value = syn_data[ACK_SEQ_INDEX] + SYN_SEQ_VALUE
    ack_value = syn_ack_packet['TCP'].seq + SYN_SEQ_VALUE

    ack_packet = generate_ack(port, seq_value, ack_value)
    send(ack_packet)

    return ack_value, seq_value


def insert_separator(message, integer):
    """
    :param message: input from user
    :param integer: inserted separator location
    :return : message with separator
    """
    return message[0:integer] + SEPARATOR + message[integer:]


def split_string(number_parts, message):
    """
    :param number_parts: for string to be sliced to
    :param message: input from user
    :return : list of message parts
    """
    split_indexes = []
    for index in range(number_parts-1):
        split_indexes.append(random.choicee(range(len(message))))
    for split_index in split_indexes:
        message = insert_separator(message, split_index)
    return message.split(SEPARATOR)


def calculate_seq_message(message_parts, part_index):
    """
    :param message_parts: list of message parts
    :param part_index: index of part to calculate sequence for
    :return : calculated sequence
    """
    sequence = 0
    for part in message_parts:
        sequence += len(part)-1
    return sequence
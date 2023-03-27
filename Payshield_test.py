#!/usr/bin/python3
# Commandline utility for testing Payshield HSM (9000, 10K)
# it will generate some keys and then perform crypto functions
# like generate PINblock, generate CVV, translate PINBlock
#
#     Copyright (C) 2023 Steve Wilson
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse, socket, string, inspect
from ipaddress import ip_address
from typing import Tuple
from struct import *

VERSION = "0.1"
MSG_HDR_LEN = 4 # should match message header config in QH on HSM

def payshield_error_codes(error_code):
    """This function maps the result code with the error message.
        I derived the list of errors and messages from the following manual:
        payShield 10K Core Host Commands v1
        Revision: A
        Date: 04 August 2020
        Doc.Number: PUGD0537 - 004

        Parameters
        ----------
         error_code: str
            The status code returned from the payShield 10k
        
         Returns
         ----------
          a string containing the message of the error code
        """
        
    PAYSHIELD_ERROR_CODE = {
        '00': 'No error',
        '01': 'Verification failure or warning of imported key parity error',
        '02': 'Key inappropriate length for algorithm',
        '04': 'Invalid key type code',
        '05': 'Invalid key length flag',
        '10': 'Source key parity error',
        '11': 'Destination key parity error or key all zeros',
        '12': 'Contents of user storage not available. Reset, power-down or overwrite',
        '13': 'Invalid LMK Identifier',
        '14': 'PIN encrypted under LMK pair 02-03 is invalid',
        '15': 'Invalid input data (invalid format, invalid characters, or not enough data provided)',
        '16': 'Console or printer not ready or not connected',
        '17': 'HSM not authorized, or operation prohibited by security settings',
        '18': 'Document format definition not loaded',
        '19': 'Specified Diebold Table is invalid',
        '20': 'PIN block does not contain valid values',
        '21': 'Invalid index value, or index/block count would cause an overflow condition',
        '22': 'Invalid account number',
        '23': 'Invalid PIN block format code. (Use includes where the security setting to implement PCI HSM '
              'limitations on PIN Block format usage is applied, and a Host command attempts to convert a PIN Block '
              'to a disallowed format.)',
        '24': 'PIN is fewer than 4 or more than 12 digits in length',
        '25': 'Decimalization Table error',
        '26': 'Invalid key scheme',
        '27': 'Incompatible key length',
        '28': 'Invalid key type',
        '29': 'Key function not permitted',
        '30': 'Invalid reference number',
        '31': 'Insufficient solicitation entries for batch',
        '32': 'AES not licensed',
        '33': 'LMK key change storage is corrupted',
        '39': 'Fraud detection',
        '40': 'Invalid checksum',
        '41': 'Internal hardware/software error: bad RAM, invalid error codes, etc.',
        '42': 'DES failure',
        '43': 'RSA Key Generation Failure',
        '46': 'Invalid tag for encrypted PIN',
        '47': 'Algorithm not licensed',
        '49': 'Private key error, report to supervisor',
        '51': 'Invalid message header',
        '65': 'Transaction Key Scheme set to None',
        '67': 'Command not licensed',
        '68': 'Command has been disabled',
        '69': 'PIN block format has been disabled',
        '74': 'Invalid digest info syntax (no hash mode only)',
        '75': 'Single length key masquerading as double or triple length key',
        '76': 'RSA public key length error or RSA encrypted data length error',
        '77': 'Clear data block error',
        '78': 'Private key length error',
        '79': 'Hash algorithm object identifier error',
        '80': 'Data length error. The amount of MAC data (or other data) is greater than or less than the expected '
              'amount.',
        '81': 'Invalid certificate header',
        '82': 'Invalid check value length',
        '83': 'Key block format error',
        '84': 'Key block check value error',
        '85': 'Invalid OAEP Mask Generation Function',
        '86': 'Invalid OAEP MGF Hash Function',
        '87': 'OAEP Parameter Error',
        '90': 'Data parity error in the request message received by the HSM',
        'A1': 'Incompatible LMK schemes',
        'A2': 'Incompatible LMK identifiers',
        'A3': 'Incompatible key block LMK identifiers',
        'A4': 'Key block authentication failure',
        'A5': 'Incompatible key length',
        'A6': 'Invalid key usage',
        'A7': 'Invalid algorithm',
        'A8': 'Invalid mode of use',
        'A9': 'Invalid key version number',
        'AA': 'Invalid export field',
        'AB': 'Invalid number of optional blocks',
        'AC': 'Optional header block error',
        'AD': 'Key status optional block error',
        'AE': 'Invalid start date/time',
        'AF': 'Invalid end date/time',
        'B0': 'Invalid encryption mode',
        'B1': 'Invalid authentication mode',
        'B2': 'Miscellaneous key block error',
        'B3': 'Invalid number of optional blocks',
        'B4': 'Optional block data error',
        'B5': 'Incompatible components',
        'B6': 'Incompatible key status optional blocks',
        'B7': 'Invalid change field',
        'B8': 'Invalid old value',
        'B9': 'Invalid new value',
        'BA': 'No key status block in the key block',
        'BB': 'Invalid wrapping key',
        'BC': 'Repeated optional block',
        'BD': 'Incompatible key types',
        'BE': 'Invalid key block header ID',
        'D2': 'Invalid curve reference',
        'D3': 'Invalid Key Encoding',
        'E0': 'Invalid command version number'
    }

    return PAYSHIELD_ERROR_CODE.get(error_code, "Unknown error")

def test_printable(input_str):
    return all(c in string.printable for c in input_str)

def establish_connection(hsm_ip, hsm_port, hsm_proto):
    connection=None
    try:
        buffer = 4096
        if hsm_proto == "tcp":
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.connect((str(hsm_ip), int(hsm_port)))
    except ConnectionError as e:
        print("Connection issue: ", e)
    response = get_hsm_status(connection, buffer)
# decode response from JK and display HSM s/n, LMKs etc

    return(connection)

def get_hsm_status(conn, buffer):
    header = "TEST"
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'JK' # get instananeous HSM status
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    # try to decode the result code contained in the reply of the payShield
    response = conn.recv(buffer)
    validate_response(message, response, header, host_command)
    return response 

def validate_response(message, response, header, host_command):
    if len(response) < 2 + MSG_HDR_LEN + 2: # 2 bytes for len + 2 header len + 2 for command
        error_handler("Incomplete response received", message, response, header)
    else:
        verb_returned = response[2 + MSG_HDR_LEN:][:2]
        verb_sent = host_command[MSG_HDR_LEN:][:2]
        verb_expected = verb_sent[0:1] + chr(ord(verb_sent[1:2]) + 1)
        if verb_returned != verb_expected.encode():
            error_handler("Response code was not as expected from command sent", message, response, header)

    response_len = int.from_bytes(response[:2], byteorder='big', signed=False)
    if len(response) - 2 != response_len:
        error_handler("Length mismatch", message, response, header)
    response_code = 2 + MSG_HDR_LEN +1
    print("Called from: ", inspect.stack()[1].function)
    print("Response code: ", response_code, payshield_error_codes(response_code))
    print("Command sent/received: ", verb_sent, "==>", verb_returned.decode())
    print_sent_rcvd(message, response, header)
    return

def error_handler(error, message, response, header):
    print("ERROR :", error)
    print_sent_rcvd(message, response, header)
    sys.exit()

def print_sent_rcvd(message, response,header):
    print("Header :", header)
    print("Header length :", MSG_HDR_LEN)
    # don't print ascii if msg or resp contains non printable chars
    if test_printable(message[2:].decode("ascii", "ignore")):
        print("sent data (ASCII) :", message[2:].decode("ascii", "ignore"))
    print("sent data (HEX) :", bytes.hex(message))
    if test_printable((response[2:]).decode("ascii", "ignore")):
        print("received data (ASCII):", response[2:].decode("ascii", "ignore"))
    print("received data (HEX) :", bytes.hex(response))
    return




###########################################################################################################
# Main code starts here
###########################################################################################################

parser = argparse.ArgumentParser(prog='Payshied_test.py')
parser.add_argument("--hsm", help="IP address of HSM to be targetted", type=ip_address)
parser.add_argument("--port", help="port to target HSM on (default: 1500)")
parser.add_argument("--proto", help="Protocol to use to connect to HSM, can be tcp, udp or tls (default=tcp)", default="tcp", choices=["tcp", "udp", "tls"], type=str.lower)
args = parser.parse_args()

if args.hsm is None:
    exit("You need to specifiy an HSM IP or hostname")
if args.port is None:
    if args.proto == "tls":
        args.port = 2500
    else: args.port = 1500
print ("HSM="+str(args.hsm)+" PORT="+str(args.port)+" PROTO="+args.proto)
hsm_conn=establish_connection(args.hsm, args.port, args.proto)
hsm_conn.close()

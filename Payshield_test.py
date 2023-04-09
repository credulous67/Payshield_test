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

import sys, argparse, socket, string, inspect, secrets, datetime, base64, time, subprocess
from ipaddress import ip_address
from baluhn import generate # need to dnf install python3-baluhn
from typing import Tuple
from struct import *
from dateutil.relativedelta import *

VERSION = "0.1"
MSG_HDR_LEN = 4 # should match message header config in QH on HSM
KB_DEC_TABLE="L7E852B114933025E9389968E16B8CAAB"
V_DEC_TABLE="0097D0017F96042F"

class bcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def payshield_error_codes(error_code):
    """This function maps the result code with the error message.
        I derived the list of errors and messages from the following manual:
        payShield 10K Core Host Commands v1
        Revision: A
        Date: 04 August 2020
        Doc.Number: PUGD0537 - 004

        Parameters
        ----------

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
            connection.settimeout(120)
            connection.connect((str(hsm_ip), int(hsm_port)))
    except TimeoutError as e:
        print("Unexpected error, connection",e)
        exit()
    except Exception as e:
        print("Unexpected error, connection",e)
        exit()
    return(connection, buffer)

def get_hsm_details(conn, buffer):
    h, l=get_hsm_status(conn, buffer)
# work out which LMK you are targetting
    host_command = 'TARG' + 'NC' # get LMK KCV & firmware
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    h['target_kcv']=response[str_ptr:str_ptr+6].decode() # only first 6 digits of 16 digit KCV
    target_id=999
    for i in range(h['#LMKs']):
        h, l=get_lmk_kcv(i, h, l, conn, buffer)
        if l[i]['KCV'] == h['target_kcv']:
            h['target_id'] = l[i]['id']
            h['target_lmkalgorithm'] = l[i]['algorithm']
            h['target_lmkscheme'] = l[i]['scheme']
    return h, l

def get_lmk_kcv(id, h, l, conn, buffer):
    header = "LKCV"
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'NC%0' + str(id) # get LMK KCV & firmware
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    #print("LMK details:", hsm_details['LMK'])
    l[id]['KCV']=response[str_ptr:str_ptr+6].decode() # only first 6 digits of 16 digit KCV
    str_ptr += 16 #get past KCV
    h['firmware']=response[str_ptr:str_ptr+9].decode()
    return h, l


def get_hsm_status(conn, buffer):
    h={}
    l={}
    header = "STAT"
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'JK' # get instananeous HSM status
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
# decode response from JK and display HSM s/n, LMKs etc
    # try to decode the result code contained in the reply of the payShield
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    h['hsm_serno'] = response[str_ptr:str_ptr + 12].decode()
    str_ptr += 12 # get past serial number
    h['date'] = response[str_ptr+4:str_ptr+6].decode() + '/' + response[str_ptr+2:str_ptr+4].decode() + '/20' + response[str_ptr:str_ptr+2].decode()
    str_ptr += 6 # get past date
    h['time'] = response[str_ptr:str_ptr+2].decode() + ':' + response[str_ptr+2:str_ptr+4].decode() + ':' + response[str_ptr+4:str_ptr+6].decode()
    str_ptr += 6 # get past time
    if args.debug:
        print("State flags:", response[str_ptr:str_ptr+7].decode())
    str_ptr += 6 # get upto tamper state
    if int(response[str_ptr:str_ptr+1].decode()) != 1:
        error_handler('Unit appears to be in tamper state', message, response)
    str_ptr += 1 # get past tamper
    h['#LMKs'] = int(response[str_ptr:str_ptr+2].decode())
    str_ptr += 2 # get past LMKs
    h['#testLMKs'] = int(response[str_ptr:str_ptr+2].decode())
    str_ptr += 2 # get past test LMKs
    h['#oldLMKs'] = int(response[str_ptr:str_ptr+2].decode())
    str_ptr += 2 # get past old LMKs
    for i in range(h['#LMKs'] ):
        l[i]={}
        l[i]['id']=response[str_ptr:str_ptr+2].decode()
        str_ptr+=2 # get past id
        l[i]['authorised']=int(response[str_ptr:str_ptr+1].decode())
        str_ptr+=1 # get past auth'd
        l[i]['#auth']=int(response[str_ptr:str_ptr+2].decode())
        str_ptr+=2 # get past #auth
        l[i]['scheme']=LMK_scheme(response[str_ptr:str_ptr+1].decode())
        str_ptr+=1 # get past scheme
        l[i]['algorithm']=LMK_algo(int(response[str_ptr:str_ptr+1].decode()))
        str_ptr+=1 # get past algorithm
        l[i]['status']=live_test(response[str_ptr:str_ptr+1].decode())
        str_ptr+=1 # get past status
        x = response[str_ptr:].find('\x14'.encode())
        if x != -1:
            l[i]['comment']=response[str_ptr:str_ptr+x].decode()
        str_ptr += x+1
    return h, l

def LMK_algo(code):
    algo_code = {
            0: '3DES 2Key',
            1: '3DES 3Key',
            2: 'AES 256bit'
    }
    return algo_code.get(code, 'Unknown')
def live_test(code):
    lt_code = {
            'L': 'Live',
            'T': 'Test'
    }
    return lt_code.get(code, 'Unknown')
def LMK_scheme(code):
    lmk_code = {
            'K': 'Keyblock',
            'V': 'Variant'
    }
    return lmk_code.get(code, 'Unknown')

def validate_response(message, response):
    len_in_response = int.from_bytes(response[:2], byteorder='big', signed=False)
    if len(response) - 2 != len_in_response: # 2 bytes for message length are not included
        error_handler("Response length mismatch", message, response)
    else:
        verb_sent = message[2 + MSG_HDR_LEN:][:2].decode()
        verb_expected = verb_sent[0:1] + chr(ord(verb_sent[1:2]) + 1)
        verb_returned = response[2 + MSG_HDR_LEN:][:2].decode()
        if verb_returned != verb_expected:
            error_handler("Response code does not match command sent", message, response)

    error_code = response[2 + MSG_HDR_LEN + 2:][:2].decode()
    if int(error_code) <= 2: # I have made an assumption here that most times <=2 is usually OK
        if args.debug:
            print("Command sent/received:", verb_sent, "==>", verb_returned)
            print_sent_rcvd(message, response)
        str_pointer = 2
        return str_pointer
    else:
        print("Error code: ", error_code, payshield_error_codes(error_code))
        error_handler("Error code <> 0 in respone", message, response)

def error_handler(error, message, response):
    print("Error trapped by function:", inspect.stack()[1].function)
    print("ERROR :", error)
    print_sent_rcvd(message, response)
    sys.exit()

def print_sent_rcvd(message, response):
    header = message[2:2 + MSG_HDR_LEN].decode()
    print("Header :", header)
    print("Header length :", MSG_HDR_LEN)
    # don't print ascii if msg or resp contains non printable chars
    if test_printable(message[2:].decode("ascii", "ignore")):
        print("sent data (ASCII) :", message[2:].decode("ascii", "ignore"))
    else:
        print("sent data (HEX) :", bytes.hex(message))
    if test_printable((response[2:]).decode("ascii", "ignore")):
        print("received data (ASCII):", response[2:].decode("ascii", "ignore"))
    else:
        print("received data (HEX) :", bytes.hex(response))
    return

def generate_keys(conn, buffer, lmk_algo, lmk_scheme):
    key_details={}
    if lmk_scheme == 'keyblock':
        key_details['DEC_TABLE']=KB_DEC_TABLE
    else:
        key_details['DEC_TABLE']=V_DEC_TABLE

    header = "KEYS"
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)

# Create ZPK #1
    if lmk_scheme == 'keyblock':
        host_command = header + 'A00FFFS#72T2N00N00'
    else:
        host_command = header + 'A00001U'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    k=response[str_ptr:].decode()
    zk=key_details['ZPK1']={}
    zk['kcv']=k[-6:]
    zk['key']=k[:-6]
    print("\tZPK#1:   ", zk['key'], "KCV:", zk['kcv'])

# Create ZPK #2
    if lmk_scheme == 'keyblock':
        host_command = header + 'A00FFFS#72T2N00E00'
    else:
        host_command = header + 'A00001U'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    k=response[str_ptr:].decode()
    zk=key_details['ZPK2']={}
    zk['kcv']=k[-6:]
    zk['key']=k[:-6]
    print("\tZPK#2:   ", zk['key'], "KCV:", zk['kcv'])

# Create PVK (IBM3624)
    if lmk_scheme == 'keyblock':
        host_command = header + 'A00FFFS#V1T2N00E00'
    else:
        host_command = header + 'A00002U'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    k=response[str_ptr:].decode()
    pk=key_details['IBMPVK']={}
    pk['kcv']=k[-6:]
    pk['key']=k[:-6]
    print("\tIBM PVK: ", pk['key'], "KCV:", pk['kcv'])

# Create PVK (Visa PVV)
    if lmk_scheme == 'keyblock':
        host_command = header + 'A00FFFS#V2T2N00E00'
    else:
        host_command = header + 'A00002U'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    k=response[str_ptr:].decode()
    pk=key_details['VISAPVK']={}
    pk['kcv']=k[-6:]
    pk['key']=k[:-6]
    print("\tVisa PVK:", pk['key'], "KCV:", pk['kcv'])

# Create CVK
    if lmk_scheme == 'keyblock':
        host_command = header + 'A00FFFS#C0T2N00E00'
    else:
        host_command = header + 'A00402U'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    k=response[str_ptr:].decode()
    ck=key_details['CVK1']={}
    ck['kcv']=k[-6:]
    ck['key']=k[:-6]
    print("\tCVK:     ", ck['key'], "KCV:", ck['kcv'])

# Create RSA key pair
    lmk_id=h['target_id']
    if lmk_scheme == 'keyblock':
        host_command = header + 'EI2102402#0000'
    else:
        host_command = header + 'EI2102402'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    tstamp=time.strftime("%Y%m%d%H%M%S")
    fname='EI_'+'lmk'+lmk_id+"_"+tstamp+'rcvd'
    r=open(fname, 'wb')
    r.write(response)
    r.close
    # find end of public key (HEX 02 03 01 00 01)
    search_EoP = response.find(b'\x02\x03\x01\x00\x01')
    if search_EoP:
        pub=response[10:search_EoP+5]
        priv=response[search_EoP+5+4:] # Extra 4 is to skip the private key length
        bits=get_bit_length(pub)
    fname='EI_'+'lmk'+lmk_id+"_pub"+tstamp+'.der'
    p=open(fname, 'wb')
    p.write(pub)
    p.close()
    fname='EI_'+'lmk'+lmk_id+"_priv"+tstamp+'.der'
    p=open(fname, 'wb')
    p.write(priv)
    p.close()
    rk=key_details['RSA']={}
    rk['public']=pub
    rk['private']=priv
    rk['bits']=bits
    print("\tRSApub-",rk['bits'],"  (HEX):", bytes.hex(rk['public']))
    print("\tRSApriv-",rk['bits']," (HEX):", bytes.hex(rk['private']))

    if args.debug:
        print(key_details)
    return key_details

def get_bit_length(pub_key):
    return 'unknown'

def generate_cards():
    card_details={}
    card_details['mastercard']={}
    card_details['visa']={}
    x=datetime.datetime.now()
    random = secrets.SystemRandom()

# Create test Mastercard
    e = random.randint(0,55)
    y=x+relativedelta(months=+e)
    mm=str(y.month).zfill(2)
    yy=str(y.year-2000).zfill(2)
    exp_date=mm + yy
    r = str(random.randint(500000000000000,599999999999999))
    card = r + str(generate(r))
    c=card_details['mastercard']
    c['PAN']=card
    c['expiry']=exp_date
    print("\tPAN:", c['PAN'], "EXP:", c['expiry'])

# Create test Visa
    e = random.randint(0,55)
    y=x+relativedelta(months=+e)
    mm=str(y.month).zfill(2)
    yy=str(y.year-2000).zfill(2)
    exp_date=mm + yy
    r = str(random.randint(400000000000000,499999999999999))
    card = r + str(generate(r))
    c=card_details['visa']
    c['PAN']=card
    c['expiry']=exp_date
    print("\tPAN:", c['PAN'], "EXP:", c['expiry'])

    if args.debug:
        print(card_details)
    return card_details

def derive_IBM_pin(conn, buffer, pvk, pan):
    header = "dPIN"
    encdec=key_details['DEC_TABLE']
    print("\tDeriving natural IBM PIN (EE)", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'EE' + pvk + '0000FFFFFFFF' + '04' + pan[-13:-1] + encdec + "P1234567890ABCDEF"
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    pinblock=response[str_ptr:].decode()
    print("PINblock:", pinblock)
    return pinblock

def verify_IBM_pin(conn, buffer, zpk, zpkkcv, pvk, pinblock, pan):
    header = "vPIN"
    encdec=key_details['DEC_TABLE']
    print("\tVerifying IBM PIN (EA) under ZPK(", zpkkcv, ")", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'EA' + zpk + pvk + '12' + pinblock + '01' + '04' + pan[-13:-1] + encdec + "P1234567890ABCDEF" + '0000FFFFFFFF'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    error_code = int(response[2 + MSG_HDR_LEN + 2:][:2].decode())
    if error_code == 0 or error_code == 2: # 02 because double length PVK
        print(bcolours.OKGREEN, True, bcolours.ENDC)
        return True
    else:
        print(bcolours.FAIL, False, bcolours.ENDC)
        return False

def generate_random_pin(conn, buffer, pan):
    header = "gPIN"
    print("\tGenerating random PIN (JA)", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'JA' + pan[-13:-1] + '04'
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    pinblock=response[str_ptr:].decode()
    print("PINblock:", pinblock)
    return pinblock
    
def verify_random_pin(conn, buffer, zpk, zpkkcv, pinblock, pan, lmkpin):
    header = "vPIN"
    encdec=key_details['DEC_TABLE']
    print("\tVerifying random PIN (BE) under ZPK(", zpkkcv, ")", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'BE' + zpk + pinblock + '01' + pan[-13:-1] + lmkpin
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    error_code = int(response[2 + MSG_HDR_LEN + 2:][:2].decode())
    if error_code == 0 or error_code == 2: # 02 because double length PVK
        print(bcolours.OKGREEN, True, bcolours.ENDC)
        return True
    else:
        print(bcolours.FAIL, False, bcolours.ENDC)
        return False

def generate_cvv(conn, buffer, cvk, pan, expiry_date, service_code):
    header="gCVV"
    print("\tGenerating CVV (CW)", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'CW' + cvk + pan + ';' + expiry_date + service_code
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    cvv=response[str_ptr:].decode()
    print("CVV:",cvv)
    return cvv

def verify_cvv(conn, buffer, cvv, cvk, pan, expiry_date, service_code):
    header="vCVV"
    print("\tValidating CVV (CY):", cvv, end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'CY' + cvk + cvv + pan + ';' + expiry_date + service_code
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    error_code = int(response[2 + MSG_HDR_LEN + 2:][:2].decode())
    if error_code == 0:
        print(bcolours.OKGREEN, True, bcolours.ENDC)
        return True
    else:
        print(bcolours.FAIL, False, bcolours.ENDC)
        return False

def translate_pinblock_lmk_zpk(conn, buffer, zpk, kcv, pan, pinblock, lmk_scheme):
    header="xL2Z"
    print("\tTranslating pinblock (JG) from LMK to ZPK(", kcv,") ISO format 0 / Thales format 1", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'JG' + zpk + '01' + pan[-13:-1] + pinblock
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    pinblock=response[str_ptr:].decode()
    print("PINblock:", pinblock)
    return pinblock

def translate_pinblock_zpk_zpk(conn, buffer, zpk1, kcv1, zpk2, kcv2, pan, pinblock, lmk_scheme):
    header="xZ2Z"
    print("\tTranslating pinblock (CC) from ZPK(", kcv1,") to ZPK(", kcv2, ")", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'CC' + zpk1 + zpk2 + '12' + pinblock + '01' + '01' + pan[-13:-1]
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    str_ptr += 2 # get past PIN length
    pinblock=response[str_ptr:-2].decode() # omit last 2 chars (dest pin block format
    print("PINblock:", pinblock)
    return pinblock

def generate_pvv(conn, buffer, pvk, pvkkcv, pinblock, pan):
    header="xZ2Z"
    print("\tGenerating PVV (DG) using PVK(", pvkkcv, ")", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'DG' + pvk + pinblock + pan[-13:-1] + '0' # 0 at end is PVKI (0-6)
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    pvv=response[str_ptr:].decode()
    print("PVV:", pvv)
    return pvv

def verify_pvv(conn, buffer, zpk, zpkkcv, pvk, pinblock, pan, pvv):
    header="vPVV"
    print("\tValidating PVV (EC) from ZPK(", zpkkcv, "):", pvv, end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    host_command = header + 'EC' + zpk + pvk + pinblock + '01' + pan[-13:-1] + '0' + pvv
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    error_code = int(response[2 + MSG_HDR_LEN + 2:][:2].decode())
    if error_code == 0:
        print(bcolours.OKGREEN, True, bcolours.ENDC)
        return True
    else:
        print(bcolours.FAIL, False, bcolours.ENDC)
        return False

def generate_signature(conn, buffer, message, privkey, lmkscheme):
    header="gRSA"
    print("\tGenerate signature for MSG=", message, ":", end=' ')
    if len(header) > MSG_HDR_LEN:
        sys.exit("Length of message header too long. HEADER :", header)
    msg_size = str(len(message)).zfill(4)
    key_size = str(len(privkey)).zfill(4)
    key_size = bytes(str(len(privkey)).zfill(4), 'ascii')
    print()
    print("MSG_size:", msg_size)
    print("KEY_size:", key_size)
    if lmkscheme == 'keyblock':
        host_command = header + 'EW' + '060104'+ msg_size + message + ';99FFFF' + bytes.hex(privkey)
    else:
        host_command = header + 'EW' + '060104'+ msg_size + message + ';99' + bytes.hex(key_size) + bytes.hex(privkey)
    size = pack('>h', len(host_command))
    message = size + host_command.encode()
    conn.send(message)
    response = conn.recv(buffer)
    str_ptr = validate_response(message, response)
    str_ptr += 8 # get us part header, response code & error code to the meat of the message
    error_code = int(response[2 + MSG_HDR_LEN + 2:][:2].decode())
    sig_len=response[str_ptr:4].decode()
    str_len += 4
    signature=response[str_ptr:].decode()
    print("Sig len:", sig_len)
    print("Signature:", signature)
    return sig_len, signature


###########################################################################################################
# Main code starts here
###########################################################################################################

parser = argparse.ArgumentParser(prog='Payshied_test.py')
parser.add_argument("--hsm", help="IP address of HSM to be targetted", type=ip_address)
parser.add_argument("--port", help="port to target HSM on (default: 1500)")
parser.add_argument("--proto", help="Protocol to use to connect to HSM, can be tcp, udp or tls (default=tcp)", default="tcp", choices=["tcp", "udp", "tls"], type=str.lower)
parser.add_argument("--debug", help="Enable debugging to see HSM traces", action='store_true')
args = parser.parse_args()

if args.hsm is None:
    exit("You need to specifiy an HSM IP or hostname")
if args.port is None:
    if args.proto == "tls":
        args.port = 2500
    else: args.port = 1500
if args.debug:
    print ("HSM="+str(args.hsm)+" PORT="+str(args.port)+" PROTO="+args.proto)
hsm_conn, buffer=establish_connection(args.hsm, args.port, args.proto)
# h - hsm_details
# l - lmk_details
h, l = get_hsm_details(hsm_conn, buffer)
print()
print("You are connected to HSM:", h['hsm_serno'], "on", h['date'], "at", h['time'])
print("HSM is running firmware version:", h['firmware'], "and it has", h['#LMKs'], "LMKs")
for i in range (h['#LMKs']):
    a=l[i]
    if int(h['target_id']) == i:
        print(bcolours.OKGREEN + "LMK id:", i, "KCV:", a['KCV'], "ALGORITHM:", a['algorithm'], "SCHEME:", a['scheme'], "COMMENT:", a['comment'] + bcolours.ENDC)
    else:
        print("LMK id:", i, "KCV:", a['KCV'], "ALGORITHM:", a['algorithm'], "SCHEME:", a['scheme'], "COMMENT:", a['comment'])
print("You are targetting LMK id:", h['target_id'], "and this is a", h['target_lmkscheme'], h['target_lmkalgorithm'], "LMK")
print()
if args.debug:
    print(h)
    print(l)
if __name__ == '__main__':
    Cont=''
    while not Cont in ['yes', 'no']:
        Cont = input('OK to continue? (type yes or no) ').lower()
    if Cont == 'no':
        connection.close()
        sys.exit()
print("Creating collateral")
card_details=generate_cards()
key_details=generate_keys(hsm_conn, buffer, h['target_lmkalgorithm'].lower(), h['target_lmkscheme'].lower())
for card in card_details:
    c=card_details[card]
    print()
    print("Performing crypto for card", c)

# Perform CVV stuff
    print("CVV Crypto")
    kc=key_details['CVK1']
    c['cvv']=generate_cvv(hsm_conn, buffer, kc['key'], c['PAN'], c['expiry'], '000')
    verify_cvv(hsm_conn, buffer, c['cvv'], kc['key'], c['PAN'], c['expiry'], '000')
    random = secrets.SystemRandom()
    rand_cvv = str(random.randint(0,999)).zfill(3)
    verify_cvv(hsm_conn, buffer, rand_cvv, kc['key'], c['PAN'], c['expiry'], '000')

# Perform PIN stuff using IBM method
    print("PIN Crypto - IBM method")
    kp=key_details['IBMPVK']
    c['IBMpinblockLMK']=derive_IBM_pin(hsm_conn, buffer, kp['key'], c['PAN'])
    kz1=key_details['ZPK1']
    kz2=key_details['ZPK2']
    c['IBMpinblockZPK1']=translate_pinblock_lmk_zpk(hsm_conn, buffer, kz1['key'], kz1['kcv'], c['PAN'], c['IBMpinblockLMK'], h['target_lmkscheme'])
    c['IBMpinblockZPK2']=translate_pinblock_zpk_zpk(hsm_conn, buffer, kz1['key'], kz1['kcv'], kz2['key'], kz2['kcv'], c['PAN'], c['IBMpinblockZPK1'], h['target_lmkscheme'])
    verify_IBM_pin(hsm_conn, buffer, kz1['key'], kz1['kcv'], kp['key'], c['IBMpinblockZPK1'], c['PAN'])
    verify_IBM_pin(hsm_conn, buffer, kz2['key'], kz2['kcv'], kp['key'], c['IBMpinblockZPK2'], c['PAN'])

# Perform PIN stuff using random PIN
    print("PIN Crypto - random PIN")
    c['pinblockLMK']=generate_random_pin(hsm_conn, buffer, c['PAN'])
    kz1=key_details['ZPK1']
    kz2=key_details['ZPK2']
    c['pinblockZPK1']=translate_pinblock_lmk_zpk(hsm_conn, buffer, kz1['key'], kz1['kcv'], c['PAN'], c['pinblockLMK'], h['target_lmkscheme'])
    c['pinblockZPK2']=translate_pinblock_zpk_zpk(hsm_conn, buffer, kz1['key'], kz1['kcv'], kz2['key'], kz2['kcv'], c['PAN'], c['pinblockZPK1'], h['target_lmkscheme'])
    verify_random_pin(hsm_conn, buffer, kz1['key'], kz1['kcv'], c['pinblockZPK1'], c['PAN'], c['pinblockLMK'])
    verify_random_pin(hsm_conn, buffer, kz2['key'], kz2['kcv'], c['pinblockZPK2'], c['PAN'], c['pinblockLMK'])

# Perform PIN stuff using Visa method
    print("PIN Crypto - Visa method")
    kp=key_details['VISAPVK']
    c['PVV']=generate_pvv(hsm_conn, buffer, kp['key'], kp['kcv'], c['pinblockLMK'], c['PAN'])
    verify_pvv(hsm_conn, buffer, kz1['key'], kz1['kcv'], kp['key'], c['pinblockZPK1'], c['PAN'], c['PVV'])
    verify_pvv(hsm_conn, buffer, kz2['key'], kz2['kcv'], kp['key'], c['pinblockZPK2'], c['PAN'], c['PVV'])

# Perform RSA crypto
    print("RSA Crypto")
    kr=key_details['RSA']
    sig_len, signature=generate_signature(hsm_conn, buffer, 'Hello World!', kr['private'], h['target_lmkscheme'].lower())

    

    
if args.debug:
    print(card_details)
hsm_conn.close()

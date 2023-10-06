#!/bin/env python3

import struct
from sha256 import Sha256


def client_sign_msg(data):
    client_secret = b"MySecretApiToken"
    api_sig = Sha256(client_secret + data).digest()

    return api_sig


def my_server(data, api_sig):
    def is_valid_cmd(cmd):
        # some cmds have arguments, split them
        cmd = cmd.split(b'=', 1)
        return cmd[0] in (b'StoreMyImage', b'ReturnSpace', b'ChangePasswordTo')

    client_secret = b"MySecretApiToken"
    if Sha256(client_secret + data).digest() != api_sig:
        raise Exception('Server: not a valid request!')

    cmds = data.split(b'\0')
    for cmd in cmds:
        if is_valid_cmd(cmd):
            print(f"Server executing: {cmd}")


cmd = b"StoreMyImage\0ReturnSpace\0"
valid_api_sig = client_sign_msg(cmd)
print("Client sending cmd...")
my_server(cmd, valid_api_sig)

# Evils below



















def construct_evil_api_call(cmd, orig_sig, cmd_to_append):
    sha256 = Sha256()
    # 'resume' the hash operation
    sha256.mlen = 64
    sha256.h = list(struct.unpack('>IIIIIIII', orig_sig))

    # Append data to the hash
    sha256.update(cmd_to_append)

    # Next construct the new cmd
    # Note that the secret length must be guessed somehow
    secret_len = 16
    new_cmd = cmd + sha256.pad(secret_len + len(cmd)) + cmd_to_append
    return (new_cmd, sha256.digest())


input('Hit a key for evils..')

cmd_to_append = b"\0ChangePasswordTo=12345678"
evil_cmd, forged_api_sig = construct_evil_api_call(cmd, valid_api_sig, cmd_to_append)
print("Evil attacker sending a cmd...")
my_server(evil_cmd, forged_api_sig)

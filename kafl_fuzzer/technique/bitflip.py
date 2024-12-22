# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style bitflip mutations (deterministic stage).
"""

def mutate_seq_walking_bits(data, func, skip_null=False, effector_map=None):

    for i in range(len(data)):
        orig = data[i]

        if effector_map:
            if not effector_map[i]:
                continue
        if skip_null and not data[i]:
            continue

        for j in range(8):
            data[i] ^= 0x80 >> j
            func(data, label="afl_flip_1/1")
            data[i] = orig


def mutate_seq_two_walking_bits(data, func, skip_null=False, effector_map=None):
    if len(data) == 0: return

    for i in range(len(data)-1):

        if effector_map:
            if effector_map[i:i+2] == bytes(2):
                continue

        if skip_null and data[i:i+2] == bytes(2):
            continue
        
        orig = data[i:i+2]

        for j in range(7):
            data[i] ^= (0xc0 >> j)
            #data[i] ^= (0x80 >> j + 1)
            func(data, label="afl_flip_2/1")
            data[i] = orig[0]

        # j=7
        data[i]   ^= (0x80 >> 7)
        data[i+1] ^= (0x80 >> 0)
        func(data, label="afl_flip_2/1")
        data[i:i+2] = orig

    # special round for last byte
    i=len(data)-1
    orig = data[i]

    if effector_map and not effector_map[i]:
        return
    if skip_null and not data[i]:
        return

    for j in range(7):
        data[i] ^= (0xc0 >> j)
        #data[i] ^= (0x80 >> j + 1)
        func(data, label="afl_flip_2/1")
        data[i] = orig


def mutate_seq_four_walking_bits(data, func, skip_null=False, effector_map=None):
    if len(data) == 0: return

    for i in range(len(data)-1):

        if effector_map:
            if effector_map[i:i+2] == bytes(2):
                continue

        if skip_null and data[i:i+2] == bytes(2):
            continue

        orig = data[i:i+2]

        for j in range(5):
            data[i] ^= (0xf0 >> j)
            func(data, label="afl_flip_2/1")
            data[i] = orig[0]

        # j=5,6,7
        data[i]   ^= (0xe0 >> 5)
        data[i+1] ^= (0x80 >> 0)
        func(data, label="afl_flip_2/1")
        data[i:i+2] = orig
        
        data[i]   ^= (0xc0 >> 6)
        data[i+1] ^= (0xc0 >> 0)
        func(data, label="afl_flip_2/1")
        data[i:i+2] = orig
        
        data[i]   ^= (0x80 >> 7)
        data[i+1] ^= (0xe0 >> 0)
        func(data, label="afl_flip_2/1")
        data[i:i+2] = orig

    # special round for last byte
    i=len(data)-1
    orig = data[i]

    if effector_map and not effector_map[i]:
        return
    if skip_null and not data[i]:
        return

    for j in range(5):
        # j=0,1,2,3,4
        data[i] ^= (0xf0 >> j)
        func(data, label="afl_flip_2/1")
        data[i] = orig


def mutate_seq_walking_byte(prog, arg, func, skip_null=False):

    if skip_null:
        return

    arg.val ^= 0xFF
    func(prog, label="afl_flip_8/1")


def mutate_seq_two_walking_bytes(prog, arg, func, skip_null=False):

    if skip_null:
        return

    byte1 = (arg.val & 0xFF)
    byte2 = (arg.val >> 8) & 0xFF

    flipped_byte1 = byte1 ^ 0xFF
    flipped_byte2 = byte2 ^ 0xFF

    arg.val = (flipped_byte2 << 8) | flipped_byte1

    func(prog, label="afl_flip_8/2")


def mutate_seq_four_walking_bytes(prog, arg, func, skip_null=False):

    if skip_null:
        return
    
    byte1 = (arg.val & 0xFF)
    byte2 = (arg.val >> 8) & 0xFF
    byte3 = (arg.val >> 16) & 0xFF
    byte4 = (arg.val >> 24) & 0xFF

    flipped_byte1 = byte1 ^ 0xFF
    flipped_byte2 = byte2 ^ 0xFF
    flipped_byte3 = byte3 ^ 0xFF
    flipped_byte4 = byte4 ^ 0xFF

    arg.val = (
        (flipped_byte4 << 24) |
        (flipped_byte3 << 16) |
        (flipped_byte2 << 8) |
        flipped_byte1
    )

    func(prog, label="afl_flip_8/4")

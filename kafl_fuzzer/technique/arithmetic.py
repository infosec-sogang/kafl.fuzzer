# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Reimplementation of AFL-style arithmentic mutations (deterministic stage).
"""

from kafl_fuzzer.technique.helper import *


def mutate_seq_8_bit_arithmetic(prog, arg, func, skip_null=False, arith_max=AFL_ARITH_MAX):

    label="afl_arith_1"

    if skip_null:
        return

    orig = arg.val
    for j in range(1, arith_max + 1):

        r1 = (orig + j) & 0xff
        r2 = (orig - j) & 0xff

        if is_not_bitflip(orig^r1):
            arg.val = r1
            func(prog, label)

        if is_not_bitflip(orig^r2):
            arg.val = r2
            func(prog, label)


def mutate_seq_16_bit_arithmetic(prog, arg, func, skip_null=False, arith_max=AFL_ARITH_MAX):

    label="afl_arith_2"

    orig = arg.val

    if skip_null:
        return

    for j in range(1, arith_max + 1):

        r1 = (orig + j) & 0xffff
        r2 = (orig - j) & 0xffff

        if orig^r1 > 0xff and is_not_bitflip(orig^r1):
            arg.val = r1
            func(prog, label)

        if orig^r2 > 0xff and is_not_bitflip(orig^r2):
            arg.val = r2
            func(prog, label)


def mutate_seq_32_bit_arithmetic(prog, arg, func, skip_null=False, arith_max=AFL_ARITH_MAX):

    label="afl_arith_4"

    orig = arg.val

    if skip_null:
        return

    for j in range(1, arith_max + 1):

        r1 = (orig + j) & 0xffffffff
        r2 = (orig - j) & 0xffffffff

        if orig^r1 > 0xffff and is_not_bitflip(orig^r1):
            arg.val = r1
            func(prog, label)

        if orig^r2 > 0xffff and is_not_bitflip(orig^r2):
            arg.val = r2
            func(prog, label)


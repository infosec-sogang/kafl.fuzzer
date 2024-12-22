# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style 'interesting values' mutations (deterministic stage).
"""

from kafl_fuzzer.technique.helper import *


def mutate_seq_8_bit_interesting(prog, arg, func, skip_null=False):

    label="afl_int_1"
    orig = arg.val

    if skip_null:
        return

    for value in interesting_8_Bit:
        if (is_not_bitflip(orig ^ value) and
            is_not_arithmetic(orig, value, 1)):
                arg.val = value
                func(prog, label=label)



def mutate_seq_16_bit_interesting(prog, arg, func, skip_null=False, arith_max=AFL_ARITH_MAX):

    label="afl_int_2"
    orig = arg.val

    if skip_null:
        return

    for value in interesting_16_Bit:
        if (is_not_bitflip(orig ^ value) and
            is_not_arithmetic(orig, value, 2, arith_max=arith_max) and
            is_not_interesting(orig, value, 2, 0)):
                arg.val = value
                func(prog, label=label)




def mutate_seq_32_bit_interesting(prog, arg, func, skip_null=False, arith_max=AFL_ARITH_MAX):

    label="afl_int_4"
    orig = arg.val

    if skip_null:
        return

    for value in interesting_32_Bit:

        if (is_not_bitflip(orig ^ value) and
            is_not_arithmetic(orig, value, 4, arith_max=arith_max) and
            is_not_interesting(orig, value, 4, 0)):
                arg.val = value
                func(prog, label=label)


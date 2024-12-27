from kafl_fuzzer.manager.node import *
from kafl_fuzzer.manager.statistics import *
from kafl_fuzzer.worker.syscall_manager import *
from kafl_fuzzer.common.logger import *
from kafl_fuzzer.worker.mutation_manager import *
from kafl_fuzzer.worker.syscall_manager import *
import pickle
import json
import sys

def process_testcase(input_file, output_file):
    try:
        with open(input_file, "rb") as f:
            result = pickle.loads(f.read())
            tc = result.to_testcase()
            with open(output_file, 'w') as json_file:
                json.dump(tc, json_file, indent=4)
        print(f"Testcase successfully written to {output_file}")
    except Exception as e:
        print(f"Error processing files: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pickle_to_json.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    process_testcase(input_file, output_file)

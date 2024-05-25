# opcode_info.py
#
# Given either an input file or directory, computes a CSV of opcode statistics
# including cycle counts, and registers and flags changed

import sys
import os
import gzip
import json
import re
import csv

from collections import Counter

# Define the flags of the Intel 8088 CPU by their bit positions
FLAGS_8088 = [
    "c",  # Carry Flag
    "R",   # Reserved, always 1
    "p",  # Parity Flag
    "R",   # Reserved, always 0
    "a",  # Auxiliary Carry Flag
    "R",   # Reserved, always 0
    "z",  # Zero Flag
    "s",  # Sign Flag
    "t",  # Trap Flag
    "i",  # Interrupt Enable Flag
    "d",  # Direction Flag
    "o",  # Overflow Flag
    "R",  # Reserved
    "R",   # Reserved
    "R",   # Reserved
    "R"    # Reserved
]

FLAGS_SHORT = [
    "o", "d", "i", "s", "z", "a", "p", "c" 
]    

def make_flag_str(flag_list):
    
    flag_str = ""
    for flag in FLAGS_SHORT:
        if flag in flag_list:
            flag_str += flag
        else:
            flag_str += "."
            
    return flag_str

def compare_flags(initial_flags, final_flags):
    """Compares two flags and returns the names of flags that have changed."""
    initial_flags_bin = format(initial_flags, '016b')
    final_flags_bin = format(final_flags, '016b')
    cleared_flags = [FLAGS_8088[i] for i in range(16) if (initial_flags_bin[15-i] != final_flags_bin[15-i]) and (final_flags_bin[15-i] != '1')]
    set_flags = [FLAGS_8088[i] for i in range(16) if (initial_flags_bin[15-i] != final_flags_bin[15-i]) and (final_flags_bin[15-i] != '0')]
    
    modified_flags = [FLAGS_8088[i] for i in range(16) if (initial_flags_bin[15-i] != final_flags_bin[15-i]) and (FLAGS_8088[i] != 'R')]
    unmodified_flags = [FLAGS_8088[i] for i in range(16) if (initial_flags_bin[15-i] == final_flags_bin[15-i]) and (FLAGS_8088[i] != 'R')]
    
    return (modified_flags, cleared_flags, set_flags, unmodified_flags)
    
def get_flags_from_state(test_obj):
        
    initial_flags = test_obj['initial']['regs']['flags']
    final_flags = initial_flags
    
    if 'flags' in test_obj['final']['regs']:
        final_flags = test_obj['final']['regs']['flags']
        
    return (initial_flags, final_flags)
    
def get_flag_states_from_flags(final_flags):
    flag_states = {}
    final_flags_bin = format(final_flags, '016b')
    for i in range(16):
        flag_states[FLAGS_8088[i]] = final_flags_bin[15-i]

    return flag_states    
        
def sort_flag_list(flags):
    order = 'odiszapc'
    order_index = {char: index for index, char in enumerate(order)}

    # Sort the list based on the defined order
    return sorted(flags, key=lambda x: order_index.get(x, float('inf')))

def strip_prefixes(arr):
    
    prefixes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0xF2, 0xF3}

    # Find the index of the first element that should not be skipped
    for index, value in enumerate(arr):
        if value not in prefixes:
            return arr[index:]

    # If all values are in the skip list, return an empty list
    return []

def min_max_keys(d):
    # Filter the dictionary to include only entries where the value is greater than 0
    filtered_keys = [key for key, value in d.items() if value > 0]

    # Check if the filtered list is not empty
    if filtered_keys:
        min_key = min(filtered_keys)
        max_key = max(filtered_keys)
        return min_key, max_key
    else:
        return 0, 0


def detect_exception(mem_list):
    last_addr = None
    consecutive_count = 0
    
    # Iterate over the list of memory arrays
    for current_addr in mem_list:
        
        # Check if the add is less than 0x400 and follows consecutively
        if current_addr < 0x400:
            if last_addr is None:
                # A true IVT lookup will start at an address that is a multiple of 4.
                if current_addr % 4 == 0:
                    consecutive_count += 1
                else:
                    return False
                
            elif current_addr == last_addr + 1:
                consecutive_count += 1
                # Check if four consecutive addrs have been found
                if consecutive_count == 4:
                
                    #print(f"Got ivt read: {current_addr:05X}")
                    return True
            else:
                # Reset counter if the sequence breaks
                consecutive_count = 1
        else:
            # Reset counter if addr is not less than 0x400
            consecutive_count = 0
        
        # Update last_addr to the current addr
        last_addr = current_addr
    
    # Return False if no sequence found
    return False

class OpcodeInfo:
    def __init__(self, test_data, base, extension=None):
        # Initialize a dictionary to store opcode information
        self.op_data = test_data
        self.opcode = base
        self.extension = extension
        self.stats = {}
       
    def process(self):      
        
        self.stats['opcode'] = hex(strip_prefixes(self.op_data[0]['bytes'])[0])[2:]
        if not self.stats['opcode']:
            throw("bad opcode!")
        
        self.stats['op_ext'] = self.format_opcode()
        
        if int(self.stats['opcode'], 16) != int(self.opcode):
            file_opcode = self.stats['opcode']
            scanned_opcode = self.opcode
            
            if file_opcode is None:
                file_opcode = 0
                
            if scanned_opcode is None:
                scanned_opcode = 0
            
            
            print(f"Opcode mismatch! File says {int(file_opcode, 16):02X}, byte scanned was {int(scanned_opcode, 16):02X}")
            sys.exit(1)
            
        self.stats['total'] = self.total_executions()
        
        self.stats['exceptions'] = self.all_exceptions()
        
        self.stats['cycles_hist'] = self.cycle_stats()
        (self.stats['min_cycles'], self.stats['max_cycles']) = min_max_keys(self.stats['cycles_hist'])
        
        self.stats['regschanged'] = self.registers_changed()
        self.stats['regschanged'].sort()
        
        (self.stats['fetches'], self.stats['fetches_hist'], self.stats['next_fetches'], self.stats['next_fetches_hist'] ) = self.all_fetches()
        
        (self.stats['mem_reads'], self.stats['mem_reads_hist']) = self.all_reads()
        (self.stats['mem_writes'], self.stats['mem_writes_hist']) = self.all_writes()
        self.stats['avg_next_fetches'] = self.stats['next_fetches'] / self.stats['total']
 
        (self.stats['min_reads'], self.stats['max_reads']) = min_max_keys(self.stats['mem_reads_hist'])
        (self.stats['min_writes'], self.stats['max_writes']) = min_max_keys(self.stats['mem_writes_hist'])
        (self.stats['min_fetches'], self.stats['max_fetches']) = min_max_keys(self.stats['fetches_hist'])
        (self.stats['min_next_fetches'], self.stats['max_next_fetches']) = min_max_keys(self.stats['next_fetches_hist'])
 
        (self.stats['modified_flags'], 
         self.stats['cleared_flags'], 
         self.stats['always_cleared_flags'],
         self.stats['set_flags'], 
         self.stats['always_set_flags']) = self.all_flags()
 
        self.stats['modified_flags'] = sort_flag_list(self.stats['modified_flags'])
        self.stats['cleared_flags'] = sort_flag_list(self.stats['cleared_flags'])
        self.stats['always_cleared_flags'] = sort_flag_list(self.stats['always_cleared_flags'])
        self.stats['set_flags'] = sort_flag_list(self.stats['set_flags'])
        self.stats['always_set_flags'] = sort_flag_list(self.stats['always_set_flags'])
        #self.stats['unmodified_flags'] = sort_flag_list(self.stats['unmodified_flags'])
 
    def results(self):
        return self.stats
 
    def format_opcode(self):
        out_string = f"{self.opcode:02X}"
        
        if self.extension and self.extension != -1:
            out_string += f".{self.extension}"
        
        return out_string
            
    def total_executions(self):
        """Return the total number of opcode executions recorded."""
        return len(self.op_data)
        
    def cycle_stats(self):
        cycles = Counter()
        
        for (i, test_obj) in enumerate(self.op_data):
            cycles[len(test_obj['cycles'])] += 1
                
        return cycles

    def registers_changed(self):
        changed = {}
        
        for (i, test_obj) in enumerate(self.op_data):
            for reg in test_obj['final']['regs']:
                changed[reg] = True
                
        return [key for key in changed.keys() if key != 'ip' and key != 'flags']
        
    def all_exceptions(self):
    
        total_exceptions = 0
        
        for (i, test_obj) in enumerate(self.op_data):
            exception = detect_exception(self.test_read_addrs(test_obj))
            
            total_exceptions += int(exception)
            
        return total_exceptions
        
    def test_fetches(self, test_obj):
    
        fetches = 0
        in_code_fetch = False
        
        for (i, cycle) in enumerate(test_obj['cycles']):
                
            # We may not start in T1 or T2 can thus can't capture the bus state. 
            # So assume if the first cycle has a segment status of CS, we're in 
            # a code fetch.
            if i == 0 and cycle[2] == "CS":
                in_code_fetch = True
            
            if cycle[7] == "CODE":
                in_code_fetch = True
            elif cycle[7] != "PASV":
                in_code_fetch = False
            
            if in_code_fetch and cycle[8] == "T3":
                fetches += 1
                
        return fetches
        
    def test_read_addrs(self, test_obj):
        addrs = []
        
        in_memr = False
        for (i, cycle) in enumerate(test_obj['cycles']):
    
            if cycle[7] == "MEMR":
                in_memr = True
            elif cycle[7] != "PASV":
                in_memr = False
            
            if in_memr and cycle[8] == "T3":
                # Add latch to list of read addresses
                addrs.append(cycle[1])
                
        return addrs
        
    def test_reads(self, test_obj):
        reads = 0
        
        in_memr = False
        for (i, cycle) in enumerate(test_obj['cycles']):
    
            if cycle[7] == "MEMR":
                in_memr = True
            elif cycle[7] != "PASV":
                in_memr = False
            
            if in_memr and cycle[8] == "T3":
                reads += 1
                
        return reads
        
    def test_writes(self, test_obj):
        writes = 0
        
        in_memw = False
        for (i, cycle) in enumerate(test_obj['cycles']):
    
            if cycle[7] == "MEMW":
                in_memw = True
            elif cycle[7] != "PASV":
                in_memw = False
            
            if in_memw and cycle[8] == "T3":
                writes += 1
                
        return writes        
        
    def all_fetches(self):
        fetches = 0
        next_fetches = 0
        total_fetches = 0
        fetches_hist = Counter()
        total_next_fetches = 0
        next_fetches_hist = Counter()
        
        for (i, test_obj) in enumerate(self.op_data):
            next_fetches = 0
            fetches = 0
            
            fetches = self.test_fetches(test_obj)
            next_fetches = fetches
            #print(fetches)

            # Every instruction has to fetch itself, so subtract instruction length - 1 
            # (We start cycles with the first byte read from the queue)
            next_fetches -= len(test_obj['bytes']) - 1
            # Every instruction fetches the next instruction, don't count that fetch
            next_fetches -= 1
            
            if next_fetches < 0:
                print("Next Fetch underflow!")
                next_fetches = 0
                
            total_fetches += fetches
            
            fetches_hist[fetches] += 1
            next_fetches_hist[next_fetches] += 1

                
            total_next_fetches += next_fetches
        return (total_fetches, fetches_hist, total_next_fetches, next_fetches_hist)
        
    def all_reads(self):
        total_reads = 0
        reads_hist = Counter()
        
        for (i, test_obj) in enumerate(self.op_data):
            reads = self.test_reads(test_obj)
            total_reads += reads

            reads_hist[reads] += 1
            
        return (total_reads, reads_hist)
        
    def all_writes(self):
        total_writes = 0
        writes_hist = Counter()
        
        for (i, test_obj) in enumerate(self.op_data):
            writes = self.test_writes(test_obj)
            total_writes += writes

            writes_hist[writes] += 1
            
        return (total_writes, writes_hist)     

    def all_flags(self):
        
        mod_dict = {}
        set_dict = {}
        cleared_dict = {}
        always_set_dict = {}
        always_cleared_dict = {}
    
        for flag in FLAGS_8088:
            set_dict[flag] = False
            cleared_dict[flag] = False
            mod_dict[flag] = False
            always_set_dict[flag] = True
            always_cleared_dict[flag] = True
        
        set_dict["R"] = False
        cleared_dict["R"] = False
        always_set_dict["R"] = False
        always_cleared_dict["R"] = False
        mod_dict["R"] = False
        
        for (i, test_obj) in enumerate(self.op_data):
        
            if 'flags' in test_obj['final']['regs']:
                final_flags = test_obj['final']['regs']['flags']
            else:
                final_flags = test_obj['initial']['regs']['flags']
                
            final_flag_states = get_flag_states_from_flags(final_flags)
        
            try:
                (initial_flags, final_flags) = get_flags_from_state(test_obj)
                (modified_flags, cleared_flags, set_flags, unmodified_flags) = compare_flags(initial_flags, final_flags)
            except:
                print(f"Flag error: Failed to get final flags from state in test: {i}")
                sys.exit(1)
                
            for flag in cleared_flags:
                mod_dict[flag] = True
                cleared_dict[flag] = True
            
            for flag in set_flags:
                mod_dict[flag] = True
                set_dict[flag] = True
                           
            for flag in FLAGS_8088:
                if final_flag_states[flag] == '0':
                    always_set_dict[flag] = False
                if final_flag_states[flag] == '1':
                    always_cleared_dict[flag] = False                           
                           
        final_set_flags = [key for key, value in set_dict.items() if value]
        final_cleared_flags = [key for key, value in cleared_dict.items() if value]
        final_modified_flags = [key for key, value in mod_dict.items() if value]
    
        #modified_flags = [key for key, value in mod_dict.items() if True]
        #unmodified_keys = [key for key in unmodified if unmodified[key] and not modified.get(key, True)]
        
        always_set_flags = [key for key, value in always_set_dict.items() if value]
        always_set_flags = [flag for flag in always_set_flags if flag in final_modified_flags]

        always_cleared_flags = [key for key, value in always_cleared_dict.items() if value]
        always_cleared_flags = [flag for flag in always_cleared_flags if flag in final_modified_flags]
        
        return (final_modified_flags, final_cleared_flags, always_cleared_flags, final_set_flags, always_set_flags)
            

def read_json_from_gzip(filename):
    with gzip.open(filename, 'rt') as f:
        data = json.load(f)
    return data


def process_file(input_filename):
    data = read_json_from_gzip(input_filename)
    
    (base, suffix) = parse_filename(input_filename)
            
    oi = OpcodeInfo(data, base, suffix)
    oi.process()
    results = oi.results()
    
    print(json.dumps(results, indent=2))
        
def format_flags(char_list):
    # Define the template string
    template = "odiszapc"
    
    # Create a set from the input list for faster lookup
    char_set = set(char_list)
    
    # Build the output string based on the template
    # Include characters from the input if they are in the template and in the right position,
    # otherwise, add a period '.'
    result = ''.join(char if char in char_set else '.' for char in template)
    
    return result        

def parse_filename(file_path):

    filename = os.path.basename(file_path)
    
    # Extract the hexadecimal number (first two characters)
    hex_number = filename[:2]

    # Convert hex number to an integer
    base_number = int(hex_number, 16)

    # Check for a suffix of the form .N and extract it if present
    suffix_part = filename.split('.')[-1]
    if suffix_part.isdigit():
        suffix_number = int(suffix_part)
    else:
        suffix_number = -1  # Default if no suffix

    return base_number, suffix_number

def is_valid_filename(filename):
    pattern = re.compile(r'^([0-9a-fA-F]{2})(\.[0-7])?')
    return bool(pattern.match(filename))
        
def sort_filenames(filenames):
    # Sort, placing invalid filenames at the end
    sorted_filenames = sorted(
        filenames,
        key=lambda x: parse_filename(x) if is_valid_filename(x) else (float('inf'), float('inf'))
    )
    return sorted_filenames     
        
def process_directory(input_path, output_csv_path=None):
    
    all_results = []
    print('[')
    
    csv_data = []
    
    filenames = os.listdir(input_path)
    valid_filenames = [fname for fname in filenames if is_valid_filename(fname)]
    sorted_filenames = sorted(valid_filenames, key=parse_filename)
    
    for filename in sorted_filenames:
        file_path = os.path.join(input_path, filename)
        if os.path.isfile(file_path):
        
            data = read_json_from_gzip(file_path)
            
            (base, suffix) = parse_filename(file_path)
            
            oi = OpcodeInfo(data, base, suffix)
            oi.process()
            result = oi.results()
            all_results.append(result)
            
            results_str = json.dumps(result, indent=2)
            results_str += ','
            
            print(results_str)
    
    print(']')
    
    if output_csv_path is not None:        
        for (i, result) in enumerate(all_results):
            
            csv_line = {}
            
            csv_line['op'] = result['op_ext']
            csv_line['total'] = result['total']
            csv_line['min_cycles'] = result['min_cycles']
            csv_line['max_cycles'] = result['max_cycles']
            csv_line['regschanged'] = ','.join(result['regschanged'])
            csv_line['ivt_hits'] = result['exceptions']
            csv_line['min_reads'] = result['min_reads']
            csv_line['max_reads'] = result['max_reads']
            csv_line['min_writes'] = result['min_writes']
            csv_line['max_writes'] = result['max_writes']
            csv_line['min_fetches'] = result['min_fetches']
            csv_line['max_fetches'] = result['max_fetches']
            csv_line['min_next_fetches'] = result['min_next_fetches']
            csv_line['max_next_fetches'] = result['max_next_fetches']
            csv_line['avg_next_fetches'] = result['avg_next_fetches']
            
            csv_line['f_mod'] = format_flags(result['modified_flags'])
            csv_line['f_set'] = format_flags(result['always_set_flags'])
            csv_line['f_clr'] = format_flags(result['always_cleared_flags'])
            
            csv_data.append(csv_line)
            
        # Create the output dictionary for CSV export.
        with open(output_csv_path, mode='w', newline='') as file:
            
            fieldnames = csv_data[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_data)

def main():

    if len(sys.argv) < 2:
        print("Usage: python opcode_info.py <input_filename or directory> [dir_output_summary.csv]")
        sys.exit(1)

    path = sys.argv[1]
    
    if os.path.isfile(path):
        process_file(path)
    elif os.path.isdir(path):
        if sys.argv == 2:
            process_directory(path)
        else:
            process_directory(path, sys.argv[2])
    else:
        print("Error, couldn't determine path.")
        sys.exit(1)

if __name__ == "__main__":
    main()
    
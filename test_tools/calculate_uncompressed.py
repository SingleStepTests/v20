# calculate_uncompressed.py
#
# Given a directory path, this utility will calculate the uncompressed 
# size of all *.gz files within, if you're curious. Saves wear on your SSD!

import os
import gzip
import struct
import sys

def get_uncompressed_size(file_path):
    with open(file_path, 'rb') as f:
        # Seek to the last 4 bytes of the file
        f.seek(-4, 2)
        # Read the last 4 bytes
        uncompressed_size = struct.unpack('<I', f.read(4))[0]
    return uncompressed_size

def scan_directory(directory):
    total_size = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.gz'):
                file_path = os.path.join(root, file)
                uncompressed_size = get_uncompressed_size(file_path)
                total_size += uncompressed_size
                print(f'File: {file_path}, Uncompressed size: {uncompressed_size} bytes')
                
    total_size_gib = total_size / (2**30)
    print(f'Total uncompressed size of all gzipped files: {total_size} bytes ({total_size_gib:.2f} GiB)')

def main():
    if len(sys.argv) != 2:
        print("Usage: python calculate_uncompressed.py <directory_path>")
        return
    
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print("The provided path is not a directory.")
        return

    scan_directory(directory)

if __name__ == '__main__':
    main()
# histogram_pairs.py
#
# Create a histogram using matplotlib comparing opcodes from two different test suites.
# Good for comparing the same opcode betweeen architectures.

import sys
import gzip
import json
import re
import matplotlib.pyplot as plt
import os

def read_json_from_gzip(filename):
    with gzip.open(filename, 'rt') as f:
        data = json.load(f)
    return data

def get_name(data):
    for entry in data:
        words = entry['name'].split()
        for word in words:
            if word.lower().startswith(('rep', 'es', 'cs', 'ds', 'ss')):
                continue
            else:
                return word
    return None

def check_bytes(array):
    prefix_values = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65}
    for value in array:
        if value in prefix_values:
            return False
    return True

def generate_histogram(ax, data, title):
    cycle_lengths = [len(entry['cycles']) for entry in data if check_bytes(entry['bytes'])]
    
    ax.set_xlabel('Cycle Length')
    ax.set_ylabel('Frequency')
    ax.set_title(title)
    ax.grid(True)
    
    # Histogram
    counts, bins, patches = ax.hist(cycle_lengths, bins=range(0, max(cycle_lengths) + 2), edgecolor='black')
    
    # Add labels to each bar
    bin_centers = 0.5 * (bins[:-1] + bins[1:])  # Calculate the center of each bin
    for bin_center, count in zip(bin_centers, counts):
        if count > 0:  # Only label bars with counts
            ax.text(bin_center, count, str(int(count)), color='black', ha='center', va='bottom',
                    fontsize=10, fontname='Arial', fontweight='bold', multialignment='center',
                    bbox=dict(facecolor='white', edgecolor='black', boxstyle='round,pad=0.5'),
                    zorder=bin_center)  # Set z-order based on the bin center

def main(input_dir1, input_dir2, filename, title1, title2, output_filename):
    # Read data from the first directory
    input_filename1 = os.path.join(input_dir1, filename)
    data1 = read_json_from_gzip(input_filename1)
    name1 = get_name(data1)
    title1 = name1 + ' - ' + title1
    if not name1:
        print("Could not find a suitable title for the histogram in directory 1.")
        return

    # Read data from the second directory
    input_filename2 = os.path.join(input_dir2, filename)
    data2 = read_json_from_gzip(input_filename2)
    name2 = get_name(data2)
    title2 = name2 + ' - ' + title2
    if not name2:
        print("Could not find a suitable title for the histogram in directory 2.")
        return

    # Create subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

    # Generate histograms
    generate_histogram(ax1, data1, title1)
    generate_histogram(ax2, data2, title2)

    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_filename)
    plt.close()

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python histogram_pairs.py <input_dir1> <input_dir2> <filename> <title1> <title2> <output_filename>")
        sys.exit(1)

    input_dir1 = sys.argv[1]
    input_dir2 = sys.argv[2]
    filename = sys.argv[3]
    title1 = sys.argv[4]
    title2 = sys.argv[5]
    output_filename = sys.argv[6]

    main(input_dir1, input_dir2, filename, title1, title2, output_filename)

## Test Tools

 - `extract.py` Will extract a specific test by hash to a separate file. Intended for use in sharing a specific test with someone, such as when you are opening a GitHub issue.
 - `subset.py` Can create a % subset of a test suite. Useful for creating smaller test sets to use as CI tasks for validating commits or PRs as the full test suite will take as signficant time to run.
 - `opcode_info.py` Will data-mine a test suite and create a CSV file with various opcode statistics.
 - `histogram_pairs.py` Will compare two opcode files from different test suites. I used this to create the diagrams in my blog article [Exploring the NEC V20](https://martypc.blogspot.com/2024/05/exploring-nec-v20-cpu.html)
 - `calculate_uncompressed.py` Will calculate the uncompressed size of the test suite, if you're curious and don't want unnecessary wear on your SSD extracting it yourself.


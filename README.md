# Introduction

This tool reads [ClassBench](https://ieeexplore.ieee.org/abstract/document/4237157) rule-set files and generates either one of the following:
   * A textual file with 5-tuples that match each rule. The output is saved in the following format:
   ```
   [#rule]: [ip-protocol] [src-ip] [dst-ip] [src-port] [dst-port]
   ```
   
   * A textual file with Open vSwitch (OVS) flows equivalent to the ClassBench rules.
   The flows' priorities are set such that overlapping flows would keep their predecence according to their position within the ClassBench rule-set file.
   
The textual formats can be easily read and used in [packet classification benchmarks](https://alonrashelbach.com/2021/12/20/benchmarking-packet-classification-algorithms).

# Prerequisites
* A Linux operating system (also WSL)
* GNU Make, GCC, G++

* How to use
```bash
# Download submodules
./build.sh
# Compile
make
# Run with help message
./bin/util-cb-map.exe --help
```

# Others
If you happen to use this tool for an academic paper, please cite *Scaling Open vSwitch with a Computational Cache* (USENIX, NSDI 2022).

[MIT License](LICENSE).

Code contributions and bug fixes are welcome.

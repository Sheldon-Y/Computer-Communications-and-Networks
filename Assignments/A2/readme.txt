CSC 361 - TCP Analyzer
Author: Hanqi (Sheldon) Yang
Student ID: V00998854
Date: October 2025

-----------------------------------------------------
1. Description
-----------------------------------------------------
This program analyzes a given TCP capture file (.cap) and prints a detailed summary
of all TCP connections in the format specified by the assignment (outputformat.pdf).

It parses the packet trace, identifies connections, computes connection statistics
(e.g., duration, packet count, RTT, window sizes), and outputs the results
to the console in human-readable format.


2. Requirements

Python version: 3.0 or higher


3. How to Run

Run the following command from the terminal or Linux server:

    python3 tcp_analyzer.py sample-capture-file.cap


4. Output

The program prints four sections as required:

    A) Total number of connections
    B) Connections' details
    C) General statistics
    D) Complete TCP connections statistics

The format of the printed output matches the sample provided in outputformat.pdf.

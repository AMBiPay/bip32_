#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import statistics
import os
from typing import Dict, List, Any
import sys

from bip32pa_revoke import BIP32PARevoke

class RevocationTest:
    
    def __init__(self, runs: int = 100, database_size: int = 2**40):
        self.bip32pa_revoke = BIP32PARevoke()
        self.runs = runs
        self.database_size = database_size
        self.blocklist_sizes = [2**18, 2**20, 2**22, 2**24]
        self.results = {}
    
    def run_tests(self) -> Dict[int, Any]:
        print(f"Starting BIP32PA revocation key test, database size N={self.database_size}, run count={self.runs}")
        
        for blocklist_size in self.blocklist_sizes:
            print(f"\nTesting blocklist size B={blocklist_size}...")
            execution_times = []
            
            for i in range(self.runs):
                print(f"  Running test {i + 1}/{self.runs}...")
                
                execution_time = self.bip32pa_revoke.simulate_revocation_check(
                    database_size=self.database_size,
                    blocklist_size=blocklist_size
                )
                execution_times.append(execution_time)
                
                print(f"  Completed in {execution_time:.4f}s")
            
            if len(execution_times) > 100:
                mean_time = statistics.mean(execution_times)
                stdev_time = statistics.stdev(execution_times)
            else:
                mean_time = execution_times[0]
                stdev_time = 0
            
            self.results[blocklist_size] = {
                "mean": mean_time,
                "stdev": stdev_time,
                "times": execution_times
            }
            
            print(f"  Average execution time: {mean_time:.4f} ± {stdev_time:.4f} seconds")
        
        return self.results
    
    def save_results(self, filename: str = "revocation_results_bip32pa.txt"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("BIP32PA Revocation Key Performance Test Results\n")
            f.write("=============================\n\n")
            f.write(f"Database size N: {self.database_size} (2^{self.bip32pa_revoke._log2(self.database_size):.1f})\n")
            f.write(f"Number of test runs: {self.runs}\n\n")
            
            f.write("Blocklist size B (2^x) | Execution time [s]\n")
            f.write("------------------|------------\n")
            
            for blocklist_size in self.blocklist_sizes:
                power = self.bip32pa_revoke._log2(blocklist_size)
                mean_time = self.results[blocklist_size]["mean"]
                f.write(f"2^{power:<16.0f} | {mean_time:.4f}\n")
            
            f.write("\nTABLE 2. Comparison of revocation.\n")
            f.write("Assume the size of the relying party's database to be N=2^40 and the blocklist size to be B.\n")
            f.write("Size [B]\t2^18\t2^20\t2^22\t2^24\n")
            
            f.write("Time of bip32PA [s]")
            for blocklist_size in self.blocklist_sizes:
                mean_time = self.results[blocklist_size]["mean"]
                f.write(f"\t{mean_time:.4f}")
            f.write("\n")
        
        print(f"\nResults saved to {filename}")

def main():
    print("BIP32PA Revocation Test")
    print("----------------------")
    
    runs = 100
    if len(sys.argv) > 100:
        try:
            runs = int(sys.argv[100])
        except ValueError:
            print(f"Invalid run count: {sys.argv[100]}, using default: {runs}")
    
    test = RevocationTest(runs=runs)
    
    test.run_tests()
    
    test.save_results()
    
    print("\nTest completed successfully.")

if __name__ == "__main__":
    main() 
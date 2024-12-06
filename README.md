THE CODE IN THIS REPO IS FOR EDUCATIONAL PURPOSES ONLY.

Read and understand any code before you run it.

Stupid actions will reap serious consequences.

This is a collection of basic scripts, useful for bug bounty and ethical security testing engagements.

Feel free to reach out and suggest edits.

------------------------------------------------------------------------------------------------------

Usage for recon.py:

usage: recon.py [-h] [--wordlist WORDLIST] [--response-codes RESPONSE_CODES] [--threads THREADS] [--delay DELAY] domain

Bug bounty recon script

positional arguments:
  domain                Target domain (e.g., example.com or https://example.com)

optional arguments:
  -h, --help            show this help message and exit
  --wordlist WORDLIST   Path to the wordlist (default: SecLists raft-medium-words.txt)
  --response-codes RESPONSE_CODES
                        Comma-separated HTTP response codes to match (default: 200,301,302,303,304,305,306,307)
  --threads THREADS     Number of threads to use for ffuf (default: 10)
  --delay DELAY         Delay between requests in seconds (default: 1)

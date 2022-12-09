# Made by fasthands9000 for educational purposes only.
# Usage: python3 Code_Sweep.py -f filename.txt

import argparse
from termcolor import colored
import sys
import time

# Define the text to be displayed in the banner
title_text = "CODE SWEEPER"

# Define the colors to be used for the banner text
title_colors = ["red", "green", "yellow", "blue", "magenta", "cyan"]

# Print the banner
sys.stdout.write("n") 
for color in title_colors:
    sys.stdout.write(colored(title_text, color, attrs=["bold"]))
    sys.stdout.write("\n")
sys.stdout.write("\n") 

# Begin scanning for insecure functions..
print("Scanning code for insecure functions..")
time.sleep(3)
print("Here are your results:")

# define a list of bad functions
bad_functions = [
    ('eval', 'evaluates arbitrary code'),
    ('exec', 'executes arbitrary code'),
    ('import', 'imports arbitrary modules'),
    ('open', 'opens arbitrary files'),
    ('input', 'reads user input as code'),
    ('os.system', 'executes arbitrary system commands'),
    ('pickle.loads', 'loads potentially malicious data'),
    ('globals', 'returns a dictionary of global variables'),
    ('locals', 'returns a dictionary of local variables'),
    ('vars', 'returns a dictionary of an object\'s attributes'),
    ('dir', 'returns a list of an object\'s attributes'),
    ('getattr', 'gets the value of an object\'s attribute'),
    ('setattr', 'sets the value of an object\'s attribute'),
    ('locals()', 'updates and returns a dictionary of the current local symbols'),
    ('globals()', 'updates and returns a dictionary of the current global symbols')
]

# define a list of vulnerable patterns
vulnerable_patterns = [
    'password = ',
    'passwd = ',
    'secret = ',
    'db.connect(',
    'cursor.execute(',
    'http://',
]

# parse the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--filename', required=True, help='the name of the text file to be checked')
args = parser.parse_args()

# open the text file
with open(args.filename, 'r') as file:
    # iterate over the lines in the file
    for line_number, line in enumerate(file):
        # iterate over the bad functions
        for function, description in bad_functions:
            # check if the function is used in the line
            if function in line:
                # if the function is used, print a warning
                print(f'Line {line_number}: WARNING: The {function} function is considered dangerous because it {description}.')

        # iterate over the vulnerable patterns
        for pattern in vulnerable_patterns:
            # check if the pattern is used in the line
            if pattern in line:
                # if the pattern is used, print a warning
                print(f'Line {line_number}: WARNING: The {pattern} pattern is considered vulnerable and should be reviewed.')

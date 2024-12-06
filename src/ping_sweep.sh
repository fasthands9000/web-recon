#!/bin/bash

# Function to test if an IP is live
is_live() {
    ping -c 1 -W 1 "$1" > /dev/null 2>&1
    return $?
}

# Check if the input file is provided and exists
if [ ! -f "$1" ]; then
    echo "File not found!"
    exit 1
fi

# Create or empty the live.txt file
> live.txt

# Read each line of the file
while IFS= read -r ip; do
    # Skip empty lines and comments
    if [[ -z "$ip" || "$ip" == \#* ]]; then
        continue
    fi

# Test if the IP is live
    if is_live "$ip"; then
        echo "$ip is live"
        echo "$ip" >> live.txt  # Append live IPs to live.txt
    else
        echo "$ip is not live"
    fi
done < "$1"

# Output live IPs from live.txt
echo "Live IPs:"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' live.txt

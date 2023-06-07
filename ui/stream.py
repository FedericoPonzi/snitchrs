import time
import sys

# Path to the event stream file
event_stream_file = "event_stream.txt"

# Delay between sending each line (in seconds)
line_delay = 0.5

# Read events from the file and send them with a delay
with open(event_stream_file, "r") as file:
    for line in file:
        # Remove leading/trailing whitespaces and newline characters
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        print(line, flush=True)
        # Sleep for the specified delay
        time.sleep(line_delay)


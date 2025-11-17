
# Music Media Log Analyzer
# This script analyzes web server logs for a music media startup to:
# 1. Identify traffic patterns
# 2. Detect potential bot traffic
# 3. Find performance issues
# 4. Generate visualizations


import pandas as pd # For data manipulation and analysis
import matplotlib.pyplot as plt # For generating visualizations
from collections import Counter # For counting IP occurrences
import re # For parsing log lines with regular expressions
import os # For file path validation

def parse_log_line(line):
    
    # Parses a single log line into its components
    # Args:
        # line (str): A single line from the log file
    # Returns: Parsed components or None if line is invalid
    
    try:
        line = line.strip()
        if not line:
            return None
            
        # Split log line into components using regex
        # Format: IP - CODE - [TIMESTAMP] "REQUEST" STATUS SIZE "-" "USER_AGENT" DURATION
        parts = re.split(r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)" (\d+)', line)
        if len(parts) < 11: # Ensure all components exist
        
        # Regex breakdown:
        # (\S+) = IP address (group 1)
        # (\S+) = Response code (group 2)
        # (\S+) = User identifier (group 3)
        # \[(.*?)\] = Timestamp (group 4)
        # "(.*?)" = HTTP request (group 5)
        # (\d+) = Status code (group 6)
        # (\d+) = Response size (group 7)
        # "(.*?)" = Referrer (group 8)
        # "(.*?)" = User agent (group 9)

            return None
            
        ip = parts[1]          # Client IP address
        timestamp = parts[4]   # Request timestamp
        request = parts[5]     # Full HTTP request
        status = int(parts[6]) # HTTP status code
        user_agent = parts[9]  # User agent string
        
        # Skip entries with invalid timestamps
        if timestamp == "-":
            return None
            
        return {
            'ip': ip, # Client IP address
            'timestamp': timestamp, # Request timestamp (e.g., "01/07/2025:06:00:02")
            'request': request, # Full HTTP request (e.g., "GET /api/episodes HTTP/1.1")
            'status': status, # HTTP status code (200, 404, etc.)
            'user_agent': user_agent # Browser/device identifier
        }
    except Exception as e:
        print(f"Skipping malformed line: {line[:100]}... (Error: {str(e)})")
        return None

def analyze_logs(log_file):
    
    # Main analysis function that processes the log file and generates reports
    # Args:
        # log_file (str): Path to the log file
    
    print(f"\nAnalyzing log file: {log_file}")
    
    # Verify file exists before processing
    if not os.path.exists(log_file):
        print(f"Error: File '{log_file}' not found")
        return
        
    # Read and parse log file
    log_entries = []
    line_count = 0
    
    # Open file with error handling for encoding issues
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line_count += 1
            entry = parse_log_line(line)
            if entry:
                log_entries.append(entry)
    
    # Print processing statistics
    print(f"\nProcessing report:")
    print(f"- Total lines scanned: {line_count}")
    print(f"- Valid entries found: {len(log_entries)}")
    print(f"- Malformed lines: {line_count - len(log_entries)}")
    
    # Exit if no valid entries found
    if not log_entries:
        print("\nERROR: No valid entries parsed. Please check:")
        print("1. Your log format matches exactly the expected pattern")
        print("2. There are no empty or corrupted lines")
        print("\nFirst 3 lines of your file:")
        with open(log_file, 'r') as f:
            for i, line in enumerate(f):
                if i < 3:
                    print(f"{i+1}: {line.strip()}")
                else:
                    break
        return
    
    # Convert to Pandas DataFrame for analysis
    logs = pd.DataFrame(log_entries)
    
    # BASIC TRAFFIC STATISTICS
    print("\n=== Traffic Analysis ===")
    print(f"Total requests: {len(logs)}")          # Total number of requests
    print(f"Unique IPs: {logs['ip'].nunique()}")   # Count of unique IP addresses
    
    # TOP IP ADDRESSES
    ip_counts = Counter(logs['ip'])  # Count requests per IP
    print("\nTop 10 IPs by requests:")
    for ip, count in ip_counts.most_common(10):
        print(f"{ip}: {count} requests")  # Show top 10 IPs
    
    # BOT DETECTION
    bot_keywords = ['bot', 'crawl', 'spider', 'scraper', 'monitoring', 'python', 'curl', 'wget']
    logs['is_bot'] = logs['user_agent'].str.lower().str.contains('|'.join(bot_keywords))
    bot_percentage = logs['is_bot'].mean()
    print(f"\nPotential bot traffic: {logs['is_bot'].sum()} requests ({bot_percentage:.1%})")
    
    # REQUEST ANALYSIS
    logs['method'] = logs['request'].str.split().str[0]  # GET/POST/etc
    logs['path'] = logs['request'].str.split().str[1]    # Requested path
    
    print("\nHTTP Methods:")
    print(logs['method'].value_counts())  # Count of each HTTP method
    
    print("\nTop Requested Paths:")
    print(logs['path'].value_counts().head(10))  # Top 10 requested URLs
    
    print("\nHTTP Status Codes:")
    print(logs['status'].value_counts())  # Count of each status code
    
    # TIME-BASED ANALYSIS
    try:
        # Convert timestamp strings to datetime objects
        logs['datetime'] = pd.to_datetime(
            logs['timestamp'],
            format='%d/%m/%Y:%H:%M:%S',  # Matches "01/07/2025:06:00:02"
            dayfirst=True,                # Day comes first in date
            errors='coerce'               # Convert errors to NaT
        )
        
        # Remove entries with invalid timestamps
        valid_time_logs = logs.dropna(subset=['datetime'])
        time_dropped = len(logs) - len(valid_time_logs)
        
        if time_dropped > 0:
            print(f"\nNote: Dropped {time_dropped} entries with invalid timestamps")
        
        if len(valid_time_logs) > 0:
            # Set datetime as index for time-based operations
            valid_time_logs.set_index('datetime', inplace=True)
            
            # Count requests per minute
            requests_per_minute = valid_time_logs.resample('T').size()
            
            # Generate traffic visualization
            plt.figure(figsize=(14, 7))
            requests_per_minute.plot(title='Requests per Minute', color='blue')
            plt.ylabel('Number of Requests')
            plt.grid(True)
            plt.tight_layout()
            plt.savefig('requests_per_minute.png')
            print("\nSaved traffic graph to 'requests_per_minute.png'")
            
            # Identify peak traffic minute
            peak_time = requests_per_minute.idxmax()
            peak_requests = requests_per_minute.max()
            print(f"\nBusiest minute: {peak_time} with {peak_requests} requests")
        else:
            print("\nWarning: No valid timestamps available for time analysis")
    except Exception as e:
        print(f"\nCould not generate time graph: {e}")

if __name__ == '__main__':
    analyze_logs('server_logs.txt') # Analyze the existing log file.

"""
BEFORE RUNNING THE CODE IN Visucal Studio CODE:
Make sure you have your python file and
the log file in the same folder. You can check it by entering 
in the terminal: "ls", and it should show 2 folders.

First, install the Python extension package from "Extensions".

Then, install the required software/library for python: pandas and matplotlib
to do that, you can easily do it by entering in the terminal: "pip3 install pandas matplotlib"
To check if Python and pip are installed, enter first in the terminal: "python3 --version"
and "python3 -m pip --version" as it will show you where they are installed.

TO RUN THE CODE:
Enter in the terminal, "python3 log_analyzer.py" and it will
produce an output text and a traffic graph.

"""
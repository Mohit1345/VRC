# Log Analysis 

## **Overview**
The Log File Analysis Tool is a Python script designed to process web server log files, extract meaningful insights, and generate structured reports. It performs the following tasks:

1. **Count Requests per IP Address**: Identifies and counts the requests made by each IP address.
2. **Identify the Most Frequently Accessed Endpoint**: Determines the endpoint accessed the most.
3. **Detect Suspicious Activity**: Flags IP addresses involved in potential brute-force login attempts based on configurable thresholds.
4. **Output Results**: Displays the results in the terminal and saves them in a CSV file.

---

## **Features**
- **Requests Per IP Address**:
  - Extracts and counts requests made by each IP.
  - Outputs results in descending order of request counts.

- **Most Frequently Accessed Endpoint**:
  - Analyzes log entries to find the endpoint accessed most frequently.
  - Displays the endpoint and its access count.

- **Suspicious Activity Detection**:
  - Detects IPs with excessive failed login attempts (default threshold: 10).
  - Outputs flagged IPs and their failed login counts.

- **CSV Report**:
  - Saves the results in a `log_analysis_results.csv` file with the following sections:
    - **Requests per IP**: `IP Address`, `Request Count`
    - **Most Accessed Endpoint**: `Endpoint`, `Access Count`
    - **Suspicious Activity**: `IP Address`, `Failed Login Count`

---


## **Regex Explanation**

The script uses the following regex pattern to parse log entries:

```python
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<endpoint>[^\s]+) [^"]+" (?P<status>\d+) (?P<size>\d+)'
)
```

**Breakdown**:
(?P<ip>\d+\.\d+\.\d+\.\d+):

1.**Captures the IP address**
Example match: 192.168.1.1.
This part of the pattern ensures that we capture the full IP address, which consists of four sets of numbers separated by dots.
- - \[(?P<datetime>[^\]]+)\]:

2.**Captures the timestamp within square brackets**
-Example match: [03/Dec/2024:10:12:34 +0000].
-The square brackets [] are escaped using a backslash \ because they are special characters in regex. The [^]]+ ensures we capture everything inside the square brackets until the closing bracket.
"(?P<method>\w+):

3.**Captures the HTTP method (e.g., GET, POST)**
-Example match: GET.
-The \w+ captures one or more word characters (letters, digits, and underscores), which corresponds to the HTTP method.
(?P<endpoint>[^\s]+):

4.**Captures the resource or endpoint being accessed**
-Example match: /home.
-This part captures the URL or resource after the HTTP method, ensuring it doesn't capture any spaces after it.
[^"]+":

5.**Matches the HTTP version and skips unnecessary details**
-This portion captures everything between the endpoint and the next double quote ("), which typically contains the HTTP version like HTTP/1.1.
(?P<status>\d+):

6.** the HTTP status code**
-Example match: 200.
-The \d+ matches one or more digits, which corresponds to the numeric HTTP status code (e.g., 200, 404).
(?P<size>\d+):

Captures the response size in bytes.
-Example match: 512.
-Similar to the status code, \d+ is used here to capture one or more digits, which represent the size of the response in bytes.

# SSH Auth Log Analyser


#### WHAT IT DOES

The SSH Auth Log Analyser is a command-line security tool that inspects the Linux system logs to identify malicious network scanning activity. By reading through server access record, it filters out
standard system activity to pinpoint two distinct, high-risk attack types: automated brute force attacks and user enumeration attacks. This tool then compiles these row events into an easy to read,
clean summary dashboard that displays the total server activity and lists the malicious IP addresses, helping the server admins to neutralise the threats.


### Initial Thought Process:

Before getting started with the project, I was contemplating whether to just search the Internet for a sample log on which my program will operate on. Then I realised, since I'm doing this project,
I might as well do everything from scratch. I decided to make my own synthetic auth log file by writing a program called "generate_log.py". Then what I did was pass in a bunch of commonly used usernames
and also usernames that attackers use often. Then I created each line from scratch that followed a certain format. 2 formats for failed entry and 1 for successful entry. This allowed me to understand the
program I was about to write in detail and adhere to the formats that I had chosen.

### Actual Program:

My entire program basically has 4 functions that do the heavy-lifting. They are:
1. parse_line
2. detect_bruteforce
3. detect_enumeration
4. summarise

Lets dive deeper into what each function does.

### parse_line
This function is built using two distinct regular expression patterns namely FAILED and ACCEPETED in order to separate successful and unsuccessful attacks cleanly. I realised that if I tried to combine
both of them, it would make the pattern overly complicated and much more difficult to write.
The flag `(?:invalid user )?` uses a non capturing group because the script only needs to know the targeted username, not whether the system classified it as invalid during processing. Marking it
non-capturing saves computing overhead and simplifies data mapping. Finally, if a line is unrelated to an SSH auth event (like a `cron` job or a `sudo` notice), the function explicitly returns `None`. This
lets the log reader instantly skip irrelevant entries and prevents polluted event metrics.


### detect_bruteforce
This function was the hard part for me. Flagging an IP simply because it hits a specific count of failed attempts is fundamentally flawed. For example, 5 password failures spread across an 8-hour workday is
likely just a legitimate employee forgetting their credentials. However, 5 failures in 3 seconds is undeniably an automated hacking script. The key differentiator is rate, not volume.

To calculate this rate efficiently, my tool runs a two-pointer sliding window algorithm. The `right` pointer walks sequentially through sorted timestamps of failed attempts, acting as the front edge of our
inspection window. The `left` pointer acts as the trailing edge, chasing `right` and advancing ONLY if the time difference between the two pointers exceeds our allowed window duration.

Because both pointers move exclusively forward across the timelines, the collection is processed in optimal O(n) linear time per IP address. The `threshold` flag dictates the minimum number of attempts
that must fall within the window, and 'window' sets the maximum duration of that window in seconds. The defaults (5 attempts in 60 seconds) were selected to match industry-standard thresholds for
identifying basic credential-stuffing software.


### detect_enumeration
User enumeration signals a different attacking mindset. Instead of aggressively hammering a single account, an attacker moves deliberately across dozens of distinct usernames (like `root`, `postgres`,
`jenkins`, `oracle`), testing each only once. Because the per-account attempt rate stays extremely low, standard rate-based brute-force windows miss this behavior entirely. What gives it away is the
abnormal variety of usernames targeted by a single source.

The specific design choice made here was to count only failed attempts toward an IP's distinct-username set. While counting every attempt might catch a highly erratic authorized operator, it
introduces major false positives on shared network infrastructure—like corporate jump hosts or VPN gateways where many legitimate workers successfully access different accounts from a single IP address
Restricting calculations to failed tries prioritises precision and minimises alert fatigue.


### summarise
The summary builder returns a structured string instead of printing directly to standard output. This abstracts the text representation from console delivery, making it fully testable within the `pytest`
suite by allowing assertions to match strings directly.

Additionally, the user lists within the enumeration tables are programmatically truncated to a strict string limit followed by `...`. This prevents an attacker targeting hundreds of accounts from warping
the terminal grid layout or flooding the screen with unreadable blocks of text.

## Limitations

Missing Year Data: Standard syslog timestamps entirely omit the year field. The tool assumes the current calendar year by default (or relies on the manual `year` override). Consequently, a log file
tracking events across a New Year's Eve boundary will calculate intervals incorrectly.

Format Dependency: The parser is strictly tuned to OpenSSH-style log signatures. It cannot natively interpret other log variants like Nginx web traffic, Apache access text, or Windows Event XML formatting.


## Error Handlingd
Rather than crashing when encountering unexpected inputs, the tool uses defensive exceptions. If the specified log file is missing, it catches the `FileNotFoundError`and terminates cleanly with an
explicit error message. If the log file exists but is completely empty or contains only non-SSH noise (like cron or sudo events), the script safely catches the empty data pooland terminates with a
clean warning instead of throwing mathematical errors or printing corrupted, empty tables. Unrecognised lines inside a valid log are silently skipped rather than interrupting the parsing loop.


## Final Message:
Thank you for reading the README. Feel free to play with my analyser and provide me with suggestions. This is my final project for CS50P, my very own Auth Log Analyser.

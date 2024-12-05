import requests
from html import unescape
from bs4 import BeautifulSoup
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
from finger import add_fingerprint  # Importing the function to add fingerprints
from finger import fingerprints  # Importing the fingerprints list

# List of user agents to choose from
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0'
]

# Function to handle HTML entity decoding and case normalization
def normalize_body(body):
    body = unescape(body)  # Decode HTML entities (e.g., &amp; -> &)
    return body.lower()  # Convert to lowercase for case-insensitive matching

# Function to ensure all URLs have a protocol (default to http:// if missing)
def ensure_protocol(url):
    # If URL doesn't already have a protocol (http:// or https://), prepend http://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


# Function to check fingerprint with retry mechanism
def check_fingerprint_with_retry(url, fingerprints, proxies=None, timeout=10, retries=3):
    attempt = 0
    backoff_time = 1  # Start with 1 second backoff time
    while attempt < retries:
        try:
            matched_fingerprints, successful_url = check_fingerprint(url, fingerprints, proxies, timeout)
            return matched_fingerprints, successful_url
        except requests.exceptions.RequestException:
            attempt += 1
            print(f"Retrying {url} in {backoff_time:.2f}s (Attempt {attempt}/{retries})")
            time.sleep(backoff_time)
            backoff_time *= 2  # Exponentially increase backoff time (1s, 2s, 4s...)
    return [], url  # Return empty if failed after retries

# Function to check fingerprint for a given URL
def check_fingerprint(url, fingerprints, proxies=None, timeout=10):
    matched_fingerprints = []  # List to store matched fingerprints
    url = ensure_protocol(url)  # Ensure protocol is added

    try:
        headers = {'User-Agent': random.choice(USER_AGENTS)}  # Randomly select a user-agent
        response = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=timeout)
        body = response.text

        normalized_body = normalize_body(body)
        soup = BeautifulSoup(body, 'html.parser')
        title = soup.title.string if soup.title else ''
        title = title.strip().lower()  # Normalize the title

        x_powered_by = response.headers.get("X-Powered-By", "").lower()
        user_agent = response.headers.get("User-Agent", "").lower()

        # Iterate through the fingerprint rule sets
        for fingerprint in fingerprints:
            rules = fingerprint['rules']
            matched = False
            for rule in rules:
                if rule(normalized_body, title, x_powered_by, user_agent):
                    matched = True
                    break  # Stop once a rule matches

            if matched:
                matched_fingerprints.append(fingerprint['name'])

        return matched_fingerprints, url  # Return matched fingerprints and the URL with protocol

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        raise  # Raise exception to trigger retry mechanism

# Function to handle URL batch processing with real-time file writing and terminal output in green
def process_urls_from_file(filename, fingerprints, output_file, proxies=None, timeout=10, retries=3):
    try:
        with open(filename, 'r') as file:
            urls = file.readlines()

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(check_fingerprint_with_retry, url.strip(), fingerprints, proxies, timeout, retries): url.strip()
                for url in urls
            }

            # Open the output file in append mode for real-time writing
            with open(output_file, 'a') as output:  # Open in 'append' mode to avoid overwriting
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        matched_fingerprints, successful_url = future.result()
                        if matched_fingerprints:
                            # Format the result
                            result = f"{successful_url}, {', '.join(matched_fingerprints)}"
                            
                            # Output the result to the terminal in green
                            print(f"\033[92mMatched: {result}\033[0m")
                            
                            # Write the result to the output file immediately
                            output.write(result + '\n')
                            output.flush()  # Ensure the result is written immediately to the file

                    except Exception as e:
                        print(f"Error processing {url}: {e}")

        print("Batch processing complete.")
    except FileNotFoundError:
        print(f"Error: The file {filename} was not found.")
    except Exception as e:
        print(f"Error processing URLs from file: {e}")

# Function to set up proxies (both HTTP and SOCKS5)
def get_proxies(http_proxy=None, socks5_proxy=None):
    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
        proxies['https'] = http_proxy
    if socks5_proxy:
        proxies['socks5'] = socks5_proxy
    return proxies

# Function to ensure all URLs have a protocol (default to http:// if missing)
def ensure_protocol(url):
    # If URL doesn't already have a protocol (http:// or https://), prepend http://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


# Main function to parse arguments and run batch scanning
def main():
    parser = argparse.ArgumentParser(description="Batch scan URLs and detect fingerprints.")
    parser.add_argument('-u', '--url_file', type=str, help="Path to the URL file (url.txt) for batch scanning.", required=False)
    parser.add_argument('-c', '--custom_url', type=str, help="Single URL for custom scan.", required=False)
    parser.add_argument('-o', '--output_file', type=str, help="Path to the output file.", required=False)
    parser.add_argument('--http_proxy', type=str, help="HTTP Proxy to use (e.g., http://127.0.0.1:8080)", required=False)
    parser.add_argument('--socks5_proxy', type=str, help="SOCKS5 Proxy to use (e.g., socks5://127.0.0.1:1080)", required=False)
    parser.add_argument('--timeout', type=int, default=10, help="Timeout threshold in seconds for each request (default: 10)", required=False)
    parser.add_argument('--retries', type=int, default=3, help="Number of retries in case of connection failure (default: 3)", required=False)
    
    args = parser.parse_args()

    proxies = get_proxies(http_proxy=args.http_proxy, socks5_proxy=args.socks5_proxy)

    if args.output_file:
        output_file = args.output_file
    else:
        output_file = None

    if args.custom_url:
        print(f"Processing custom URL: {args.custom_url}")
        custom_url = ensure_protocol(args.custom_url)
        matched_fingerprints, successful_url = check_fingerprint_with_retry(custom_url, fingerprints, proxies, args.timeout, args.retries)
        if matched_fingerprints:
            print(f"Matched fingerprints: {', '.join(matched_fingerprints)}")
            if output_file:
                with open(output_file, 'w') as output:
                    output.write(f"{successful_url}, {', '.join(matched_fingerprints)}\n")
                    print(f"Results written to {output_file}")
        else:
            print("No matches found.")
    
    elif args.url_file:
        print(f"Processing URLs from file: {args.url_file}")
        if output_file:
            process_urls_from_file(args.url_file, fingerprints, output_file, proxies, args.timeout, args.retries)
        else:
            print("No output file specified, results will not be saved.")
    
    else:
        print("Please specify either a custom URL or a URL file for batch scanning.")

# Run the main function
if __name__ == "__main__":
    main()

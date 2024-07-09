from flask import Flask, render_template, request

app = Flask(__name__)

import argparse
import os
import random
from colorama import init, Fore
import requests

init(autoreset=True)

DEFAULT_ATTACKER = 'attacker.com'
DEFAULT_REDIRECTS = 10
DEFAULT_SSL = False
DEFAULT_METHOD = 'GET'
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'


def get_random_user_agent(user_agents):
    return random.choice(user_agents).strip()


def detect_vulnerabilities(url, wordlists, attacker, output_file, max_redirects, use_ssl, method, user_agent, verbose,
                           body, proxy, debug, recursive):
    try:
        if wordlists:
            with open(wordlists, 'r') as file:
                headers = file.readlines()
        else:
            headers = ['Host', 'Max-Forwards', 'Origin', 'Proxy-Authorization', 'Range', 'Referer', 'Upgrade',
                       'User-Agent', 'X-Forwarded-For', 'X-Forwarded-Host']

        cache_poisoning_detected = False  # Flag to track cache poisoning detection
        cors_detected = False  # Flag to track CORS

        for header in headers:
            headers_dict = {
                'Host': url.split('/')[2],
                'User-Agent': user_agent,
                header.strip(): attacker
            }

            if debug:
                print(Fore.CYAN + '[Request]')
                print(Fore.CYAN + 'URL:', url)
                print(Fore.CYAN + 'Method:', method)
                print(Fore.CYAN + 'Headers:', headers_dict)
                print(Fore.CYAN + 'Body:', body)
                print(Fore.CYAN + 'Proxy:', proxy)

            proxies = None
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }

            response = requests.request(method, url, headers=headers_dict, allow_redirects=max_redirects,
                                        verify=use_ssl, data=body, proxies=proxies)

            if debug:
                print(Fore.CYAN + '[Response]')
                print(Fore.CYAN + 'Status Code:', response.status_code)
                print(Fore.CYAN + 'Headers:', response.headers)
                print(Fore.CYAN + 'Body:', response.text)

            # Web Cache Poisoning Detected
            if not cache_poisoning_detected and (
                    'Cache-Control' in response.headers and 'private' not in response.headers['Cache-Control'] or
                    'Pragma' in response.headers and response.headers['Pragma'] == 'public' or
                    'Expires' in response.headers or
                    'ETag' in response.headers or
                    'Vary' in response.headers and response.headers.get('Vary', '').lower() in ['Origin',
                                                                                                'Accept-Encoding'] or
                    'X-Cache' in response.headers and response.headers.get('X-Cache', '').lower() in ['hit', 'miss']
            ):
                result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Potensial Web Cache Poisoning] ' + Fore.WHITE + url
                print(result)
                if output_file:
                    with open(output_file, 'a') as output:
                        output.write(result + '\n')
                cache_poisoning_detected = True

                # CORS (Cross-Origin Resource Sharing) Detected
            if 'Access-Control-Allow-Origin' in response.headers:
                allow_origin = response.headers.get('Access-Control-Allow-Origin')
                if allow_origin != '*' and attacker.lower() not in allow_origin.lower():
                    result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Potential CORS Misconfiguration]' + Fore.WHITE + url
                    print(result)
                    if output_file:
                        with open(output_file, 'a') as output:
                            output.write(result + '\n')
                    cors_detected = True

            if 'Access-Control-Allow-Credentials' in response.headers:
                allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
                if allow_credentials == 'true' and attacker.lower() not in response.headers.get(
                        'Access-Control-Allow-Origin', '').lower():
                    result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Potential CORS Misconfiguration]' + Fore.WHITE + url
                    print(result)
                    if output_file:
                        with open(output_file, 'a') as output:
                            output.write(result + '\n')
                    cors_detected = True

            if 'Access-Control-Allow-Methods' in response.headers:
                allow_methods = response.headers.get('Access-Control-Allow-Methods')
                if allow_methods and method not in allow_methods:
                    result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Potential CORS Misconfiguration]' + Fore.WHITE + url
                    print(result)
                    if output_file:
                        with open(output_file, 'a') as output:
                            output.write(result + '\n')
                    cors_detected = True

            if 'Access-Control-Allow-Headers' in response.headers:
                allow_headers = response.headers.get('Access-Control-Allow-Headers')
                if allow_headers and 'origin' not in allow_headers.lower():
                    result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Potential CORS Misconfiguration]' + Fore.WHITE + url
                    print(result)
                    if output_file:
                        with open(output_file, 'a') as output:
                            output.write(result + '\n')
                    cors_detected = True

            # Host Header Injection Detected
            elif attacker.lower() in response.headers or attacker.lower() in response.content.decode('utf-8').lower():
                result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Header: ' + header.strip() + '] ' + Fore.WHITE + url
                print(result)
                if output_file:
                    with open(output_file, 'a') as output:
                        output.write(result + '\n')
            elif verbose:
                result = Fore.RED + '[No Vulnerability] ' + Fore.YELLOW + '[Header: ' + header.strip() + '] ' + Fore.WHITE + url
                print(result)

            elif recursive:
                for header in headers:
                    detect_vulnerabilities(url, new_header.strip(), attacker, output_file, max_redirects, use_ssl,
                                           method, user_agent,
                                           verbose, body, proxy, debug, recursive=False)

    except requests.exceptions.TooManyRedirects:
        print(Fore.MAGENTA + '[Error] [Exceeded {} redirects]'.format(max_redirects))
    except requests.exceptions.SSLError as e:
        error_message = str(e)
        ssl_error = error_message.split(': ')[-1] if ': ' in error_message else error_message
        print(Fore.MAGENTA + '[Error] [SSLError] {}'.format(ssl_error))
    except requests.exceptions.RequestException as e:
        print(Fore.MAGENTA + '[Error] [{}] {}'.format(type(e).__name__, e))

@app.route('/')
def homepage():
    detect_vulnerabilities('https://security50.crossidentityqa.com', False,DEFAULT_ATTACKER, 'result.txt', DEFAULT_REDIRECTS, DEFAULT_SSL,
                           DEFAULT_METHOD, DEFAULT_USER_AGENT, False, '', None, True, False)

    print("Homepage accessed")  # Debugging statement
    return '''
        <form action="/confirm" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name"><br><br>
            <label for="age">Age:</label>
            <input type="text" id="age" name="age"><br><br>
            <label for="city">City:</label>
            <input type="text" id="city" name="city"><br><br>
            <input type="submit" value="Submit">
        </form>
    '''

@app.route("/confirm", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print("POST request received")  # Debugging statement
        n = request.form.get('name')
        a = request.form.get('age')
        c = request.form.get('city')
        return render_template('confirm.html', name=n, age=a, city=c)
    print("Invalid request method")  # Debugging statement
    return 'Invalid request method.'

if __name__ == "__main__":
    app.run(debug=True, port=5001)

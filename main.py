import requests
import hashlib
import sys


def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'encoding error{res.status_code}, enter correct api')
    return res


def count_of_leaks(hashes, hashes_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hashes_to_check:
            return count
    return 0


def pwned_api_check(password):
    shaw1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = shaw1password[:5], shaw1password[5:]
    response = request_api_data(first5_char)
    return count_of_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times, you should change your password')
        else:
            print(f'{password} is good')
    return 'done'


main(sys.argv[1:])

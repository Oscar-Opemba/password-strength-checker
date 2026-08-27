import argparse
import json
import math
import re
from common import serve

def analyze(values):
    secret = values.get('password', '')
    if not secret: return {'error': 'Enter a passphrase to evaluate.'}
    classes = sum(bool(pattern.search(secret)) for pattern in [re.compile('[a-z]'), re.compile('[A-Z]'), re.compile('[0-9]'), re.compile('[^A-Za-z0-9]')])
    pool = sum([26 if re.search('[a-z]', secret) else 0, 26 if re.search('[A-Z]', secret) else 0, 10 if re.search('[0-9]', secret) else 0, 33 if re.search('[^A-Za-z0-9]', secret) else 0])
    entropy = round(len(secret) * math.log2(pool), 1) if pool else 0
    suggestions = []
    if len(secret) < 14: suggestions.append('Prefer a longer passphrase; length is usually the most useful improvement.')
    if classes < 3: suggestions.append('Use several character classes or, better, several unrelated words.')
    if re.search(r'(.)\1\1|1234|password|qwerty|admin', secret.lower()): suggestions.append('Avoid repeated characters and common words or sequences.')
    if secret.lower() in {'password', 'password1', 'letmein', 'admin', 'qwerty'}: suggestions.append('This value is commonly guessed and should not be used.')
    score = min(100, round(entropy * 1.25))
    if secret.lower() in {'password', 'password1', 'letmein', 'admin', 'qwerty'}: score = min(score, 20)
    strength = 'weak' if score < 40 else 'moderate' if score < 70 else 'strong' if score < 90 else 'very strong'
    return {'length': len(secret), 'character_classes': classes, 'estimated_entropy_bits': entropy, 'score': score, 'strength': strength, 'suggestions': suggestions or ['No obvious weakness detected by this simple offline heuristic. Use a password manager and never reuse secrets.'], 'privacy': 'The passphrase is analyzed in memory only and is not transmitted or stored by this program.'}

def main():
    parser = argparse.ArgumentParser(description='Check passphrase quality offline; never submit real secrets to a website.')
    parser.add_argument('password', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8083)
    args = parser.parse_args()
    if args.web: serve('Password Strength Checker', [('password','Passphrase','password','Use a private example')], analyze, args.port)
    elif args.password: print(json.dumps(analyze({'password':args.password}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()

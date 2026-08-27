__version__ = "0.3.0"
import argparse
import json
import math
import re
from common import serve

COMMON_PASSWORDS={'password','password1','letmein','admin','qwerty','welcome','iloveyou'}
def analyze(values):
    secret=values.get('password','')
    if not secret: return {'error':'enter a passphrase to evaluate'}
    if len(secret)>1024: return {'error':'passphrase exceeds the 1024 character safety limit'}
    classes=sum(bool(pattern.search(secret)) for pattern in (re.compile('[a-z]'),re.compile('[A-Z]'),re.compile('[0-9]'),re.compile('[^A-Za-z0-9]')))
    pool=sum((26 if re.search('[a-z]',secret) else 0,26 if re.search('[A-Z]',secret) else 0,10 if re.search('[0-9]',secret) else 0,33 if re.search('[^A-Za-z0-9]',secret) else 0))
    entropy=round(len(secret)*math.log2(pool),1) if pool else 0; score=min(100,round(entropy*1.25))
    repeated=bool(re.search(r'(.)\1\1',secret)); common=secret.casefold() in COMMON_PASSWORDS
    if common: score=min(score,10)
    elif repeated: score=min(score,35)
    strength='weak' if score<40 else 'moderate' if score<70 else 'strong' if score<90 else 'very strong'
    suggestions=[]
    if len(secret)<14: suggestions.append('Prefer a longer passphrase made from unrelated words.')
    if classes<3: suggestions.append('Use a password manager to create a unique random secret.')
    if repeated or common or re.search(r'1234|qwerty|password|admin',secret.casefold()): suggestions.append('Avoid common words, sequences, and repeated characters.')
    return {'length':len(secret),'character_classes':classes,'estimated_entropy_bits':entropy,'score':score,'strength':strength,'suggestions':suggestions or ['No obvious weakness detected by this heuristic. Never reuse secrets.'],'privacy':'Processed in memory only; this program does not transmit, log, or store the passphrase.'}

def main():
    parser=argparse.ArgumentParser(description='Check passphrase quality offline; never submit real secrets to a website.')
    parser.add_argument('password',nargs='?'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8083)
    parser.add_argument('--version',action='version',version=__version__)
    args=parser.parse_args()
    if args.web: serve('Password Strength Checker',[('password','Passphrase','password','Use a private example')],analyze,args.port)
    elif args.password: print(json.dumps(analyze({'password':args.password}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()

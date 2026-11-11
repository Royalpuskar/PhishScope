"""Explain suspicious URL structure without opening the destination."""
import json

from urllib.parse import urlsplit, parse_qsl
import ipaddress
def analyze(data):
    results=[]
    for raw in data.get('urls',[]):
        flags=[]
        try:
            url=urlsplit(raw)
            host=url.hostname or ''
            if url.scheme not in ('http','https') or not host: raise ValueError('Only absolute HTTP(S) URLs supported')
            if url.scheme != 'https': flags.append('unencrypted-scheme')
            if url.username is not None: flags.append('embedded-userinfo')
            try: ipaddress.ip_address(host); flags.append('ip-literal-host')
            except ValueError: pass
            if any(part.startswith('xn--') for part in host.split('.')): flags.append('internationalized-host')
            if len(host.split('.'))>4: flags.append('deep-subdomain')
            if any(k.lower() in ('password','token','secret','api_key') for k,v in parse_qsl(url.query)): flags.append('sensitive-query-key')
            score=min(100,len(flags)*20)
            results.append({'url':raw,'host':host,'flags':flags,'indicator_score':score,'verdict':'review' if flags else 'no-structural-flags'})
        except ValueError as error:
            results.append({'url':raw,'error':str(error)})
    return {'results':results,'network_requests':0}

if __name__ == '__main__':
    import argparse, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Path to a JSON scenario')
    args = parser.parse_args()
    try:
        with open(args.input, encoding='utf-8') as source:
            data = json.load(source)
        if not isinstance(data, dict):
            raise ValueError('Input must be a JSON object')
        print(json.dumps(analyze(data), indent=2, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError) as error:
        print('Input error: '+str(error), file=sys.stderr)
        sys.exit(2)

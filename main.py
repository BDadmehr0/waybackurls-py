import sys
import json
import argparse
import requests
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import os
from typing import List, Tuple, Optional, Dict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dates", action="store_true", help="show date of fetch in the first column")
    parser.add_argument("--no-subs", action="store_true", help="don't include subdomains of the target domain")
    parser.add_argument("--get-versions", action="store_true", help="list URLs for crawled versions of input URL(s)")
    parser.add_argument("domain", nargs="?", help="domain to query")
    
    args = parser.parse_args()
    
    domains = []
    if args.domain:
        domains = [args.domain]
    else:
        domains = [line.strip() for line in sys.stdin if line.strip()]
    
    if args.get_versions:
        for domain in domains:
            versions = get_versions(domain)
            if versions:
                print("\n".join(versions))
        return
    
    fetch_functions = [
        get_wayback_urls,
        get_commoncrawl_urls,
        get_virustotal_urls
    ]
    
    for domain in domains:
        seen_urls = set()
        with ThreadPoolExecutor() as executor:
            futures = []
            for fn in fetch_functions:
                futures.append(executor.submit(fn, domain, args.no_subs))
            
            for future in futures:
                try:
                    results = future.result()
                    for wurl in results:
                        if wurl.url in seen_urls:
                            continue
                        seen_urls.add(wurl.url)
                        
                        if args.dates and wurl.date:
                            try:
                                dt = datetime.strptime(wurl.date, "%Y%m%d%H%M%S")
                                print(f"{dt.isoformat()} {wurl.url}")
                            except ValueError:
                                print(f"{wurl.url}")
                        else:
                            print(wurl.url)
                except Exception as e:
                    print(f"Error fetching URLs: {e}", file=sys.stderr)

class Wurl:
    def __init__(self, date: str = "", url: str = ""):
        self.date = date
        self.url = url

def get_wayback_urls(domain: str, no_subs: bool) -> List[Wurl]:
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://web.archive.org/cdx/search/cdx?url={subs_wildcard}{domain}/*&output=json&collapse=urlkey"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        wrapper = response.json()
        
        out = []
        skip = True
        for item in wrapper:
            if skip:
                skip = False
                continue
            if len(item) >= 3:
                out.append(Wurl(date=item[1], url=item[2]))
        return out
    except Exception as e:
        print(f"Wayback error: {e}", file=sys.stderr)
        return []

def get_commoncrawl_urls(domain: str, no_subs: bool) -> List[Wurl]:
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={subs_wildcard}{domain}/*&output=json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        out = []
        for line in response.text.splitlines():
            try:
                data = json.loads(line)
                out.append(Wurl(date=data.get("timestamp", ""), url=data.get("url", "")))
            except json.JSONDecodeError:
                continue
        return out
    except Exception as e:
        print(f"CommonCrawl error: {e}", file=sys.stderr)
        return []

def get_virustotal_urls(domain: str, no_subs: bool) -> List[Wurl]:
    out = []
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return out
    
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        for item in data.get("detected_urls", []):
            out.append(Wurl(url=item.get("url", "")))
        return out
    except Exception as e:
        print(f"VirusTotal error: {e}", file=sys.stderr)
        return []

def is_subdomain(raw_url: str, domain: str) -> bool:
    try:
        parsed = urlparse(raw_url)
        if not parsed.hostname:
            return False
        return parsed.hostname.lower() != domain.lower()
    except:
        return False

def get_versions(url: str) -> List[str]:
    api_url = f"http://web.archive.org/cdx/search/cdx?url={url}&output=json"
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        
        out = []
        seen_digests = set()
        first = True
        
        for item in data:
            if first:
                first = False
                continue
            if len(item) >= 6:
                digest = item[5]
                if digest in seen_digests:
                    continue
                seen_digests.add(digest)
                out.append(f"https://web.archive.org/web/{item[1]}if_/{item[2]}")
        return out
    except Exception as e:
        print(f"Error getting versions: {e}", file=sys.stderr)
        return []

if __name__ == "__main__":
    main()

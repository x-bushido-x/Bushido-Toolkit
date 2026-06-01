"""
Hash cracker module (John the Ripper style)
Supports: MD5, SHA1, SHA256, SHA512, SHA224, SHA384,
          bcrypt, NTLM, MySQL323, MySQL41, LM
"""

import hashlib
import re
import os
import time
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style


# ── Hash identification ───────────────────────────────────────────────────────

HASH_SIGNATURES = [
    # (regex pattern, name, length)
    (r'^[a-f0-9]{32}$',   'MD5',    32),
    (r'^[a-f0-9]{40}$',   'SHA1',   40),
    (r'^[a-f0-9]{56}$',   'SHA224', 56),
    (r'^[a-f0-9]{64}$',   'SHA256', 64),
    (r'^[a-f0-9]{96}$',   'SHA384', 96),
    (r'^[a-f0-9]{128}$',  'SHA512', 128),
    (r'^\$2[aby]\$\d+\$', 'bcrypt', 0),
    (r'^\$1\$',           'MD5-crypt', 0),
    (r'^\$5\$',           'SHA256-crypt', 0),
    (r'^\$6\$',           'SHA512-crypt', 0),
    (r'^[a-f0-9]{16}$',   'MySQL323', 16),
    (r'^\*[A-F0-9]{40}$', 'MySQL41', 41),
    (r'^[A-F0-9]{32}$',   'NTLM', 32),
    (r'^[a-zA-Z0-9+/]{22}={0,2}$', 'MD5-base64', 0),
]

HASH_FUNCTIONS = {
    'MD5':    lambda p: hashlib.md5(p.encode()).hexdigest(),
    'SHA1':   lambda p: hashlib.sha1(p.encode()).hexdigest(),
    'SHA224': lambda p: hashlib.sha224(p.encode()).hexdigest(),
    'SHA256': lambda p: hashlib.sha256(p.encode()).hexdigest(),
    'SHA384': lambda p: hashlib.sha384(p.encode()).hexdigest(),
    'SHA512': lambda p: hashlib.sha512(p.encode()).hexdigest(),
    'NTLM':   lambda p: _ntlm_hash(p),
    'MySQL323': lambda p: _mysql323_hash(p),
    'MySQL41':  lambda p: '*' + hashlib.sha1(hashlib.sha1(p.encode()).digest()).hexdigest().upper(),
}


def _ntlm_hash(password: str) -> str:
    """Compute NTLM hash."""
    import hashlib
    return hashlib.new('md4', password.encode('utf-16-le')).hexdigest().upper()


def _mysql323_hash(password: str) -> str:
    """Compute MySQL 3.23 (OLD_PASSWORD) hash."""
    nr  = 1345345333
    add = 7
    nr2 = 0x12345671
    for c in password:
        if c in (' ', '\t'):
            continue
        tmp = ord(c)
        nr  ^= (((nr & 63) + add) * tmp) + (nr << 8)
        nr2 += (nr2 << 8) ^ nr
        add += tmp
    result1 = nr  & 0x7FFFFFFF
    result2 = nr2 & 0x7FFFFFFF
    return f"{result1:08x}{result2:08x}"


def identify_hash(hash_str: str) -> List[str]:
    """
    Identify possible hash types from a hash string.
    Returns list of possible type names.
    """
    hash_str = hash_str.strip()
    matches  = []
    for pattern, name, _ in HASH_SIGNATURES:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append(name)
    return matches if matches else ['Unknown']


# ── Cracking engine ───────────────────────────────────────────────────────────

def _crack_chunk(hash_str: str, hash_type: str,
                 words: List[str]) -> Optional[str]:
    """Try a chunk of words against a hash. Returns plaintext or None."""
    fn = HASH_FUNCTIONS.get(hash_type)
    if not fn:
        return None

    target = hash_str.strip().lower()
    # MySQL41 is uppercase with leading *
    if hash_type == 'MySQL41':
        target = hash_str.strip().upper()

    for word in words:
        try:
            if fn(word).lower() == target or fn(word) == hash_str.strip():
                return word
        except Exception:
            continue
    return None


def _crack_bcrypt(hash_str: str, words: List[str]) -> Optional[str]:
    """Crack bcrypt hash (slow, single-threaded)."""
    try:
        import bcrypt
        for word in words:
            try:
                if bcrypt.checkpw(word.encode(), hash_str.encode()):
                    return word
            except Exception:
                continue
    except ImportError:
        print(f"  {Fore.YELLOW}[!] bcrypt not installed: pip install bcrypt{Style.RESET_ALL}")
    return None


class HashCracker:
    def __init__(self, threads: int = 8, verbose: bool = False):
        self.threads = threads
        self.verbose = verbose

    def crack(self, hash_str: str, wordlist: List[str],
              hash_type: str = 'auto') -> Dict:
        """
        Crack a single hash.
        Returns {'hash': ..., 'type': ..., 'plaintext': ..., 'cracked': bool}
        """
        hash_str = hash_str.strip()

        # Auto-detect type
        if hash_type == 'auto':
            types = identify_hash(hash_str)
            hash_type = types[0] if types else 'Unknown'

        result = {
            'hash':      hash_str,
            'type':      hash_type,
            'plaintext': None,
            'cracked':   False,
        }

        if hash_type == 'Unknown':
            result['error'] = 'Could not identify hash type'
            return result

        print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Cracking {Fore.YELLOW}{hash_type}{Style.RESET_ALL} hash: "
              f"{Fore.WHITE}{hash_str[:40]}{'...' if len(hash_str) > 40 else ''}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Wordlist size: {len(wordlist):,} words  "
              f"Threads: {self.threads}")

        start = time.time()

        # bcrypt is special — must be single-threaded
        if hash_type == 'bcrypt':
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} bcrypt is slow by design — using single thread")
            plaintext = _crack_bcrypt(hash_str, wordlist)
        else:
            plaintext = self._parallel_crack(hash_str, hash_type, wordlist)

        elapsed = time.time() - start

        if plaintext is not None:
            result['plaintext'] = plaintext
            result['cracked']   = True
            print(f"\n  {Fore.GREEN}[+] CRACKED!{Style.RESET_ALL}  "
                  f"Hash: {hash_str[:30]}...  →  "
                  f"Plaintext: {Fore.RED}{plaintext}{Style.RESET_ALL}  "
                  f"({elapsed:.1f}s)")
        else:
            print(f"\n  {Fore.YELLOW}[-] Not found in wordlist.{Style.RESET_ALL}  "
                  f"({elapsed:.1f}s, {len(wordlist):,} words tried)")

        return result

    def _parallel_crack(self, hash_str: str, hash_type: str,
                        wordlist: List[str]) -> Optional[str]:
        """Split wordlist across threads and crack in parallel."""
        chunk_size = max(1, len(wordlist) // self.threads)
        chunks     = [wordlist[i:i + chunk_size]
                      for i in range(0, len(wordlist), chunk_size)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(_crack_chunk, hash_str, hash_type, chunk)
                       for chunk in chunks]

            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result is not None:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    return result

                # Progress
                done = i + 1
                pct  = int(done / len(chunks) * 100)
                print(f"\r  [*] Progress: {pct}%  ({done}/{len(chunks)} chunks)   ",
                      end='', flush=True)

        return None

    def crack_multiple(self, hashes: List[str], wordlist: List[str],
                       hash_type: str = 'auto') -> List[Dict]:
        """Crack multiple hashes."""
        results = []
        for h in hashes:
            r = self.crack(h, wordlist, hash_type)
            results.append(r)
        return results


def print_crack_results(results: List[Dict]):
    """Print hash cracking results."""
    print(f"\n{'═' * 65}")
    print(f"  {Fore.RED}HASH CRACKING RESULTS{Style.RESET_ALL}")
    print(f"{'═' * 65}")
    print(f"  {'HASH':<35} {'TYPE':<12} {'PLAINTEXT'}")
    print(f"  {'─'*34} {'─'*11} {'─'*20}")

    for r in results:
        h         = r['hash'][:32] + ('...' if len(r['hash']) > 32 else '')
        htype     = r.get('type', '?')
        plaintext = r.get('plaintext', '')
        cracked   = r.get('cracked', False)

        if cracked:
            status = f"{Fore.GREEN}{plaintext}{Style.RESET_ALL}"
        else:
            status = f"{Fore.YELLOW}not found{Style.RESET_ALL}"

        print(f"  {Fore.WHITE}{h:<35}{Style.RESET_ALL} "
              f"{Fore.CYAN}{htype:<12}{Style.RESET_ALL} "
              f"{status}")

    cracked_count = sum(1 for r in results if r.get('cracked'))
    print(f"\n  Cracked: {Fore.GREEN}{cracked_count}{Style.RESET_ALL} / {len(results)}")
    print(f"{'═' * 65}")

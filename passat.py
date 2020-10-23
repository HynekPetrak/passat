#!/usr/bin/env python3

import binascii
import sys
import re
import argparse
import json
from fuzzywuzzy import process
from collections import Counter

VERSION = "1.6"

SYMBOLS = "~`!@#$%^&*()_\-+=}\]{[|\\\"':;?/>.<, "

stats_regex = {
    "Contains: 123": f"^.*123.*$",
    "Contains: 1234": f"^.*1234.*$",
    "Contains: space": "^(?=.*[ ]).*$",
    "Has: All lowercase": "^[a-z]+$",
    "Has: All num": "^[\d]+$",
    "Has: All uppercase": "^[A-Z]+$",
    "Has: First capital, last number": "^[A-Z].*\d$",
    "Has: First capital, last symbol": f"^[A-Z].*[{SYMBOLS}]$",
    "Has: Four digits at the end": "^.*[^\d]\d\d\d\d$",
    "Has: Single digit at the end": "^.*[^\d]\d$",
    "Has: Three digits at the end": "^.*[^\d]\d\d\d$",
    "Has: Two digits at the end": "^.*[^\d]\d\d$",
    "Has: Upper + lower + num + symbol": f"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[{SYMBOLS}]).*$",
    "Has: Lower + num + symbol": f"^(?=.*[a-z])(?=.*\d)(?=.*[{SYMBOLS}])[a-z\d{SYMBOLS}]*$",
    "Has: Upper + num + symbol": f"^(?=.*[A-Z])(?=.*\d)(?=.*[{SYMBOLS}])[A-Z\d{SYMBOLS}]*$",
    "Has: Upper + lower + num": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]*$",
    "Has: Alpha + num":    "^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d]*$",
    "Has: Alpha + symbol": f"^(?=.*[a-zA-Z])(?=.*[{SYMBOLS}])[A-Za-z{SYMBOLS}]*$",
    "Has: Upper + lower + symbol": f"^(?=.*[a-z])(?=.*[A-Z])(?=.*[{SYMBOLS}])[A-Za-z{SYMBOLS}]*$",
    "Has: Upper + lower": "^(?=.*[a-z])(?=.*[A-Z])[A-Za-z]*$",
    "Last digit is '0'": "^.*0$",
    "Last digits are '020'": "^.*020$",
    "Last digits are '19xx'": "^.*19\d\d$",
    "Last digits are '20'": "^.*20$",
    "Last digits are '2020'": "^.*2020$",
    "Last digits are '20xx'": "^.*20\d\d$",
    "Seq: 1 upper > lower > num or symbol": f"^[A-Z][a-z]+[\d{SYMBOLS}]+$",
    "Seq: 1 upper > lower > num": f"^[A-Z][a-z]+[\d]+$",
    "Seq: aplha > num > alpha": f"^[A-Za-z]+\d+[A-Za-z]+$",
    "Seq: aplha > num > symbol": f"^[A-Za-z]+\d+[{SYMBOLS}]+$",
    "Seq: aplha > num": "^[A-Za-z]+\d+$",
    "Seq: aplha > symbol > num": f"^[A-Za-z]+[{SYMBOLS}]+\d+$",
}

stats = {k: re.compile(v, re.UNICODE) for (k, v) in stats_regex.items()}

pat_regex = {
    "[a-z]": "a",
    "[A-Z]": "A",
    "[\d]": "1",
    f"[{SYMBOLS}]": "@",
}

pat_subs = {v: re.compile(k, re.UNICODE) for (k, v) in pat_regex.items()}

hex_re = re.compile("^\$HEX\[([0-9a-fA-F]*)\]$", re.UNICODE)

line_re = re.compile("(?:.*?:)?(?:.*?:)?(.*)$", re.UNICODE)


def print_counter(title, cnt, grand_total, limit=15):
    print(f"{title}")
    print("=" * len(title))
    items = cnt.most_common(limit)
    if not items:
        print("---- no data ----")
        print("")
        return
    max_width = max([len(str(i[0])) for i in items])
    for i in cnt.most_common(limit):
        value = i[1]
        percentage = 1.0 * value / grand_total
        print(f"{i[0]:<{max_width}}  {i[1]:>6}  {percentage:>6.1%}")
    print("")


def progbar(curr, total, full_progbar=40):
    frac = curr / total
    filled_progbar = round(frac * full_progbar)
    msg = 'Completed: [' + '#' * filled_progbar + ' ' * \
        (full_progbar - filled_progbar) + '] ' + '[{:>4.0%}]'.format(frac)
    if msg != progbar.last_message:
        print(msg, end='\r')
        progbar.last_message = msg
        sys.stdout.flush()


progbar.last_message = ''


def main():
    parser = argparse.ArgumentParser(
        description=f"Audit password quality v{VERSION}")
    parser.add_argument("input_file", type=str,
                        default=['-'], nargs="*",
                        help="input file names, one password per line. If ommited, read from stdin")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-f", "--freq", help="run frequency analysis for characters used",
                        action="store_true")
    parser.add_argument("--no-categories", help="don't perform fuzzy categorization, improves performance",
                        action="store_true")
    parser.add_argument("-c", "--categories", help="json file with password categories for fuzzy matching, defaults to categories.json",
                        default="categories.json")
    args = parser.parse_args()

    if not args.no_categories:
        with open(args.categories, "r") as read_file:
            categories = json.load(read_file)
        words = [x for y in categories.values() for x in y]
        word2category = {x: k for k, v in categories.items() for x in v}

    verbose = args.verbose
    cnt = Counter()
    cnt_length = Counter()
    cnt_pwd = Counter()
    cnt_root = Counter()
    cnt_regex = Counter()
    cnt_symbol = Counter()
    cnt_alpha = Counter()
    cnt_num = Counter()
    cnt_totals = Counter()
    cnt_pattern = Counter()

    sys.stdin.reconfigure(errors='replace')

    grand_total = 0
    total_valid_passwords = 0
    for f in args.input_file:
        print(f"Reading: {f}")
        if f == '-':
            f = sys.stdin.fileno()
        with open(f, 'r', errors='replace') as f:
            # to avoid newlines
            lines = f.read().splitlines()

        total = len(lines)
        print(f"Processing: {total} passwords")
        progress = 0
        valid_passwords = 0
        for l in lines:
            progress += 1

            # process line formats:
            # password
            # user:password
            # user:hash:password
            # ... and extract password only
            m = re.match(line_re, l)
            if m:
                p = m.group(1)

            # skip empty passwords
            if not p:
                continue

            valid_passwords += 1

            # convert $HEX[abcd1234] passwords
            m = re.match(hex_re, p)
            if m:
                p = binascii.unhexlify(m.group(1)).decode("latin1")

            # length stats
            cnt_length[len(p)] += 1

            # same password counting
            cnt_pwd[p] += 1
            if verbose:
                print(p)

            # letter frequency analysis
            if args.freq:
                cnt_totals["chars"] += len(p)
                for letter in p:
                    if letter.isalpha():
                        cnt_alpha[letter] += 1
                        cnt_totals["alpha"] += 1
                    elif letter.isnumeric():
                        cnt_num[letter] += 1
                        cnt_totals["num"] += 1
                    else:
                        cnt_symbol[letter] += 1
                        cnt_totals["symbol"] += 1

            # pattern counting
            pwd_pat = p
            for subst, pat in pat_subs.items():
                pwd_pat = pat.sub(subst, pwd_pat)
            cnt_pattern[pwd_pat] += 1

            # Matching various regex categories
            for cat, pat in stats.items():
                if re.search(pat, p):
                    cnt_regex[cat] += 1
                    if verbose:
                        print(cat)

            # Fuzzy matching to categories
            if len(p) > 3 and not args.no_categories and words:
                highest = process.extractOne(p, words)
                mall = process.extract(p, words)
                if verbose:
                    print(mall)
                for m in mall:
                    if m[1] > 80:
                        cnt_root[m[0]] += 1
                pw_match, score = highest
                pw_category = word2category[pw_match]
                if score < 65:
                    pw_category = 'other'
                cnt[pw_category] += 1
                if verbose:
                    print(f"{p} > {pw_match} : {score} > {pw_category}")
                    #print(f"'{p}'", highest, pw_category)

            if verbose:
                print()
            else:
                progbar(progress, total)

        grand_total += total
        total_valid_passwords += valid_passwords
        print()

    print()
    print(f"Total lines processed: {grand_total}")
    print(f"Valid passwords found: {total_valid_passwords}")
    print()
    if not args.no_categories:
        print_counter("Categories", cnt, grand_total)
        print_counter("Password base words:", cnt_root, grand_total)
    print_counter("Password length frequency:", cnt_length, grand_total)
    print_counter("Password values:", cnt_pwd, grand_total)
    print_counter("Charsets and sequences:", cnt_regex,
                  grand_total, len(stats_regex))
    print_counter("Password patterns:", cnt_pattern, grand_total, 15)
    if args.freq:
        print_counter("Most frequent alpha chars:",
                      cnt_alpha, cnt_totals["alpha"])
        print_counter("Most frequent num chars:", cnt_num, cnt_totals["num"])
        print_counter("Most frequent symbol chars:",
                      cnt_symbol, cnt_totals["symbol"])


if __name__ == '__main__':
    main()

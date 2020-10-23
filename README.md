# passat - password auditing tool

A Python tool, that analyses password sets by performing various statistics. The statistics might help to assess general password quality, common paterns, weak password based on common base words or effectiveness of password policy implementation. 

It can be used on any password sets, active directory ntds dumps, application password database dumps, credentilas collected during red team or pen test projects.

## Installation

```
git clone https://github.com/HynekPetrak/Passat.git
```
Tested with Python 3.8.2

### Requirements

On Ubuntu/Kali run:

```
apt install python3-levenshtein python3-fuzzywuzzy
```
or with pip on any system:

```
pip3 install -r requirements.txt
```

## Usage 

```
# ./passat.py -h
usage: passat.py [-h] [-v] [-f] [--no-categories] [-c CATEGORIES] [input_file [input_file ...]]

Audit password quality v1.6

positional arguments:
  input_file            input file names, one password per line. If ommited, read from stdin

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -f, --freq            run frequency analysis for characters used
  --no-categories       don't perform fuzzy categorization, improves performance
  -c CATEGORIES, --categories CATEGORIES
                        json file with password categories for fuzzy matching, defaults to categories.json

```

you may test the tool with provided sample file

```
# ./passat.py -f pwd_sample.txt
Reading: pwd_sample.txt
Processing: 823 passwords
Completed: [########################################] [100%]
```
Input file(s) can be in any of below 3 formats, one password per line:
```
password
user:password
user:hash:password
```
It's compatible with `hashcat --show` and `hashcat --show --user` output as well as with the output of John The Ripper.

## Sample results

Each statistical result has always three columns `name`, `count`, `percentage from total`.

### Base word statistics 

Common base words are defined in `categories.json`. The tool uses fyzzy matching in order to determine a potential base word for each password,

```
Password base words:
====================
pa$$          198   24.1%
pass          186   22.6%
p@$$          128   15.6%
password      126   15.3%
winter         45    5.5%
summer         35    4.3%
J.P.           28    3.4%
welcome        21    2.6%
```

### Categorization according base words

Each base word in `categories.json` belongs to certain category ...

```
Categories
==========
password      286   34.8%
other         145   17.6%
brand         137   16.6%
day_month     111   13.5%
initial        41    5.0%
sequence       31    3.8%
name           18    2.2%
location       13    1.6%
color           7    0.9%
```
### Statistics about content and sequences
```
Charsets and sequences:
=======================
Has: All lowercase                       311   37.8%
Has: Alpha + num                         304   36.9%
Seq: aplha > num                         252   30.6%
Has: Upper + lower + num                 171   20.8%
Has: First capital, last number          157   19.1%
Has: Four digits at the end              135   16.4%
Seq: 1 upper > lower > num or symbol     121   14.7%
Last digits are '20xx'                   120   14.6%
Seq: 1 upper > lower > num               105   12.8%
Has: Upper + lower                        98   11.9%
Has: Single digit at the end              79    9.6%
Has: Two digits at the end                45    5.5%
Has: First capital, last symbol           43    5.2%
Has: Upper + lower + num + symbol         41    5.0%
Contains: 123                             38    4.6%
Has: Three digits at the end              33    4.0%
Has: All num                              31    3.8%
Has: Alpha + symbol                       24    2.9%
Last digit is '0'                         23    2.8%
Has: Upper + lower + symbol               17    2.1%
Seq: aplha > num > alpha                  16    1.9%
Contains: 1234                            12    1.5%
Seq: aplha > num > symbol                 11    1.3%
Has: Lower + num + symbol                  7    0.9%
Has: All uppercase                         3    0.4%
Last digits are '19xx'                     2    0.2%
Seq: aplha > symbol > num                  1    0.1%
Last digits are '20'                       1    0.1%
Contains: space                            1    0.1%
```


### Password length frequency

```
Password lenght frequency:
==========================
10     170   20.7%
9      147   17.9%
8      127   15.4%
6      124   15.1%
7       93   11.3%
4       41    5.0%
11      25    3.0%
```
### Same password occurences
Number of occurences of every password to show some passwords are used more frequently than other. For example constant initial passwords.
```
Password values:
================
test               9    1.1%
P@55w0rd!          8    1.0%
testing            7    0.9%
Password1          7    0.9%
P@ssw0rd           7    0.9%
sqlserver          7    0.9%
sql                7    0.9%
```

### Password patterns

Show most frequent password patterns, where `A` stands for capital letter, `a` for lowercase letter, `1` for a digit and `@` for a symbol.
```
Password patterns:
==================
aaaaaa          74    9.0%
aaaaaaa         58    7.0%
aaaaaa1111      53    6.4%
aaaaaaaa        49    6.0%
Aaaaaa1111      48    5.8%
aaaa            36    4.4%
Aaaaaa          31    3.8%
aaaaaaaaa       23    2.8%
Aaaaaaa         22    2.7%
aaaaaaaa1       21    2.6%
```

### Single character frequency analysis

E.g. which symbols are being used the most:
```
Most frequent symbol chars:
===========================
!      49   50.5%
@      31   32.0%
-       5    5.2%
$       4    4.1%
)       2    2.1%
(       1    1.0%
```

## License

MIT

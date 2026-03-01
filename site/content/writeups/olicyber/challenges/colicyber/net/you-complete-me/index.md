---
title: "You Complete Me — Binary Search Word Reconstruction"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "misc", "binary-search", "python"]
difficulty: "intermediate"
summary: "A sorted word list and a known sequence of binary-search response sizes pin down a unique word character by character. Reconstruct it by matching the precounted word counts at each prefix level."
---

## The Challenge

The server implements a word-guessing game using binary search semantics over a sorted word list. The server's response lengths (number of candidate words remaining after each guess) are known in advance: `[3952, 825, 23, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1]`. The goal is to reconstruct the password that matches this exact shrinking response sequence.

## Approach

The challenge provides `words.txt` — a sorted word list. The response length after guessing a prefix is the number of words in the list that start with that prefix. Given the known sequence of response sizes, search all printable ASCII characters at each position: try appending each character to the current prefix and count how many words still match. The character that produces `risp_len[i]` words for position `i` is the correct next character.

`get_words_by_prefix` does a range scan over the sorted list: words matching prefix `c` are in `[prefix + c, prefix + next(c))`. The `trova` function recurses depth-first until the full password is found.

## Solution

```python
#!/usr/bin/env python3
import string

with open('./words.txt', 'rb') as f:
    words = list(sorted([word.strip() for word in f.readlines()]))

ascii_all = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation + '_'
risp_len = [3952, 825, 23, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1] # len delle risposte della binsearch

def next_char(char):
    return (ord(char) + 1).to_bytes(1, 'big')

def get_words_by_prefix(prefix):
    prefix, last_char = prefix[:-1], prefix[-1].to_bytes(1, 'big')
    lower_bound = prefix + last_char
    upper_bound = prefix + next_char(last_char)

    return [w for w in words if lower_bound <= w < upper_bound]

def trova(pre, pos):
    if pos == len(risp_len):
        print(pre)
        return
    
    for i in ascii_all:
        if len(get_words_by_prefix(pre + i.encode())) == risp_len[pos]:
            trova(pre + i.encode(), pos + 1)

trova(b'', 0)
```

`next_char` computes the ASCII successor byte for the range upper bound. `get_words_by_prefix` filters the sorted word list to all words whose last known byte equals `last_char` — equivalent to a binary search range query. `trova` is a depth-first backtracking search: at each position it tries every character, and if the resulting word count matches the pre-known response, it recurses one level deeper.

## What I Learned

When a server leaks the size of its binary-search window at each step, a known-response-count attack fully reconstructs the target without ever connecting to the server. It is a side-channel analogue of blind SQLi: instead of timing, the oracle is response cardinality. The sorted word list makes the range query efficient.

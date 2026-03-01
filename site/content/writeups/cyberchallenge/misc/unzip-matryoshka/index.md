---
title: "Unzip Matryoshka — 3000 Nested Zip Files"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["misc", "automation", "zip", "python", "scripting"]
difficulty: "beginner"
summary: "Automate extraction of 3000 nested zip files to retrieve the flag from the innermost archive."
---

## The Challenge

You're given `flag3000.zip`. Inside is `flag2999.zip`. Inside that is `flag2998.zip`. This nesting continues all the way down to `flag0.zip`, which finally contains `flag.txt` with the flag. Manually unzipping 3000 times is not an option.

## Approach

The pattern is entirely regular: `flagN.zip` contains `flag(N-1).zip`. Starting from 3000 and working down to 1, extract each archive to the same output directory. At each step, the next archive to process is `flag{i-1}.zip` in the output directory. After the innermost extraction, `flag.txt` contains the flag.

Python's `zipfile` module handles this cleanly in a loop. No external tools needed, no error handling complexity — just iterate from 2999 down to 1 (since `flag3000.zip` is the starter and `flag1.zip` is the last one that contains `flag0.zip` or `flag.txt`), extract each zip to the working directory, and read the final file.

## Solution

```python
import os
import zipfile

# Path to the directory containing the zip files
zip_folder = '/home/user/Downloads/flag3000.zip'

# Path to the destination folder where the extracted files will be saved
destination_folder = '/home/user/Downloads/zipdir/'

file_path = '/home/user/Downloads/flag3000.zip'
for i in range (2999, 0, -1):
    file_path = '/home/user/Downloads/zipdir/flag' + str(i) + '.zip'
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(destination_folder)
        
for i in range (0, 3000):
    os.remove("/home/user/Downloads/zipdir/flag" + str(i) + ".zip")
```

The script starts by pointing `file_path` at the outermost archive and then loops down from 2999 to 1, extracting each zip into `destination_folder`. At each step `flag{i}.zip` extracts `flag{i-1}.zip` into the same directory, so the path variable just counts down. The second loop removes leftover zips after extraction to keep the folder clean.

The paths are hardcoded to `/home/user/Downloads/` — this was written quickly during the competition to just run once and get the flag out.

## What I Learned

Nested archives are a standard CTF misc trope. The key is recognizing the pattern immediately and writing the loop before you even try to manually unzip anything. The `zipfile` module's `extractall` to a single directory approach is cleaner than creating per-level subdirectories.

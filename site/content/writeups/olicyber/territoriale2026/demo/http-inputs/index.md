---
title: "HTTP Inputs"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["web", "http", "headers", "cookies", "options-method", "requests"]
difficulty: "beginner"
summary: "Send a single HTTP OPTIONS request with the exact query param, header, cookie, and body the server expects simultaneously."
---

## The Challenge

The web endpoint validates five HTTP inputs at once:

- Query parameter: `?we_like=flags`
- Custom header: `give-me: the-flag`
- Cookie: `session_id=the_session`
- Request body: `pretty please :(`
- HTTP method: `OPTIONS`

All five must be present in the same request. Any missing piece and you get nothing useful back.

## Approach

This is a checklist challenge, not a vulnerability — the server is testing whether you understand the different places an HTTP request can carry data. Most people interact with APIs via GET or POST and never think about query strings, custom headers, cookies, body, and method as five independent channels.

The natural tool is Python's `requests` library, which exposes all five channels as explicit parameters. The method is selected by which function you call: `requests.options()`. Query params go in the `params` dict. Headers go in `headers`. Cookies go in `cookies`. The body is the `data` argument.

One request, five parameters, done.

## Solution

```python
import requests

url = "http://10.45.1.2:4001/?we_like=flags"
headers = {
    "give-me": "the-flag",
    "Content-Type": "text/plain"
}
cookies = {
    "session_id": "the_session"
}
data = "pretty please :("

print(f"Sending OPTIONS request to {url}")
response = requests.options(url, headers=headers, cookies=cookies, data=data)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

# flag{puTt1Ng_t0g3tH3r_4Ll_hTtP_1npUtS_bc7f984f}
```

`requests.options()` sends an HTTP OPTIONS request. The query parameter `?we_like=flags` is already baked into the URL string directly. `headers` adds the custom `give-me: the-flag` header. `cookies` sends `Cookie: session_id=the_session`. `data` sets the request body to the string `pretty please :(`. All five inputs land in one request — the server validates them together and returns the flag.

## What I Learned

HTTP has more input channels than most web developers regularly use. Query strings, headers, cookies, and body are all distinct and independently parsed by every web framework — this challenge just makes you use all four at once, plus a non-standard method. Worth internalizing before tackling more complex web challenges.

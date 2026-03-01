---
title: "Just a Reminder — Obfuscated JS Secret Key Recovery"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "javascript", "reverse-engineering"]
difficulty: "beginner"
summary: "The login form runs client-side JS. Deobfuscating or inspecting it reveals a hardcoded secret key used to AES-decrypt the flag — the key is plaintext at the top of the obfuscated script."
---

## The Challenge

A login page with a JS-powered check. Submitting any credentials triggers the obfuscated JS. The actual flag/secret is computed client-side using AES decryption with a hardcoded key.

## Approach

Running the script through a deobfuscator (or just inspecting the top of the file) reveals:

```javascript
var s3cr37 = 'ML4czctKUzigEeuR';
```

This is the AES key passed directly to `CryptoJS.AES.decrypt`. The rest of the obfuscation is a control-flow flattening wrapper around a simple `login_check` function that decrypts the flag using this key and prints it to the console.

Running `node file.js` (or copying the JS into the browser console) calls `login_check()` and prints the decrypted flag value.

## Solution

```javascript
// esegui con il comando node file.js
var username_field = "";
var password_field = "";

var s3cr37 = 'ML4czctKUzigEeuR';
login_check()
// ... [obfuscated body omitted] ...
function AES_decrypt(message = '', key = '') {
  var code = CryptoJS.AES.decrypt(message, key);
  var decryptedMessage = code.toString(CryptoJS.enc.Utf8);
  return decryptedMessage;
}
```

The hardcoded key `ML4czctKUzigEeuR` is the answer. The comment at the top says `// esegui con il comando node file.js` — executing the script with Node.js runs the decryption and prints the flag.

## What I Learned

Client-side "protection" using JavaScript — even obfuscated JS — is not security. Any secret embedded in JS that runs in the browser is readable by anyone who opens DevTools. Deobfuscation tools like `de4js` or `js-beautify` strip control-flow flattening in seconds; but often the plaintext secret is visible at the top before any obfuscation layer starts.

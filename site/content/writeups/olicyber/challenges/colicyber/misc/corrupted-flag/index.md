---
title: "Corrupted Flag — Fix GIF Magic Bytes then Extract Frames"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "forensics", "file-format"]
difficulty: "beginner"
summary: "The GIF has wrong magic bytes at the start. Replace the first 13 bytes with the correct GIF89a header, open the repaired file with Pillow, and iterate through frames saved as WebP to find the flag."
---

## The Challenge

A file called `corrupted_file` is provided. Opening it normally fails — any tool that sniffs the magic bytes rejects it. The task is to figure out what is wrong and fix it.

## Approach

`file corrupted_file` or a hex editor shows the first bytes are not `47 49 46 38 39 61` (GIF89a). The first 13 bytes (6-byte signature + 2-byte width + 2-byte height + 3-byte packed/background/aspect bytes) are corrupted. The rest of the file is valid GIF data.

Writing the correct magic `b"GIF89a"` followed by the original bytes from offset 13 onwards creates a valid GIF. Then Pillow's `ImageSequence.Iterator` iterates over every frame and saves them. One of the frames contains the flag as visible text or in the image content.

## Solution

```python
from PIL import ImageSequence, Image
corrupted = open("corrupted_file", "rb").read()
notcorr = open("flag.gif", "wb")
print(corrupted[:13]) # magic number sbagliati
notcorr.write(b"GIF89a" + corrupted[13:])
notcorr.close()
notcorr = Image.open("flag.gif")
i = 0
for frame in ImageSequence.Iterator(notcorr):
    i += 1
    frame.save("frame-"+str(i)+".webp",format = "WebP", lossless = True)
# la flag la si trova fra i frame salvati
```

`corrupted[:13]` prints the broken header to stderr (the inline comment says "magic number sbagliati" — wrong magic bytes). `b"GIF89a" + corrupted[13:]` pastes the correct signature while keeping all the original frame data intact. The loop saves every frame as lossless WebP — scrolling through them reveals the flag in one of the frames.

## What I Learned

Corrupted file challenges almost always corrupt the magic bytes (aka file signature) at the start — the actual data is intact. Checking the first few bytes against the expected signature for the file format, then patching the header, is the standard recovery technique. `strings` run on the corrupted file often gives a shortcut clue too.

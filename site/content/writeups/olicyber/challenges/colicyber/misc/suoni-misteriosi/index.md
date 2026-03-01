---
title: "Suoni Misteriosi — Morse Audio Decoder"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "forensics", "morse", "audio"]
difficulty: "beginner"
summary: "A WAV file carries the flag in Morse code audio. Decode it automatically with morse-audio-decoder and wrap the result in flag{...}."
---

## The Challenge

The challenge gives a WAV audio file called `comunicazione.wav`. Playing it reveals the classic dit-dah pattern of Morse code. Manual transcription is possible but tedious.

## Approach

The `morse-audio-decoder` Python library (`pip install morse-audio-decoder`) handles the entire pipeline: it reads the WAV file, detects the signal timing, segments the dots and dashes, and returns the decoded text. The output is the flag content — wrapping it in `flag{...}` gives the full flag.

## Solution

```python
from morse_audio_decoder.morse import MorseCode
morse_code = MorseCode.from_wavfile("comunicazione.wav")
out = morse_code.decode()
print("flag{" + out + "}")
```

Three lines. `from_wavfile` loads and analyses the WAV. `.decode()` converts the signal to text. The result is printed inside the flag format.

## What I Learned

Audio Morse challenges do not require manual listening. `morse-audio-decoder` automates the entire signal-to-text pipeline as long as the recording is clean enough. For noisy recordings, Audacity's spectrogram view or the `scipy` short-time Fourier transform can help isolate the Morse carrier frequency before passing to the decoder.

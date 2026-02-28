from morse_audio_decoder.morse import MorseCode
morse_code = MorseCode.from_wavfile("comunicazione.wav")
out = morse_code.decode()
print("flag{" + out + "}")

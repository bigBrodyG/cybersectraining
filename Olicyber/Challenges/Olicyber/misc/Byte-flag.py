with open("flag.png", "rb") as flag:
    text = flag.read()
    index = text.find("flag".encode())
    for i in range(index, len(text)):
        print(chr(text[i]), end="")
from zipfile import ZipFile
import os
for i in range(3000):
    with ZipFile("flag"+str(abs(i-3000))+".zip", "r") as zip:
        zip.extractall(os.path.dirname("Olicyber-WritesUp"))
    os.remove("flag"+str(abs(i-3000))+".zip")

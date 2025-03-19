# ╔╗╔╔═╗╦    ╔═╗╔═╗╔═╗╔╦╗╔╦╗╔═╗╦═╗
# ║║║║ ╦║    ╚═╗╠═╝╠═╣║║║║║║║╣ ╠╦╝
# ╝╚╝╚═╝╩═╝  ╚═╝╩  ╩ ╩╩ ╩╩ ╩╚═╝╩╚═ v4.3
# added account check

# The program was made for automation.
# This program violates NGL's terms of service, use it at your own risk!
# Also, I don't support using it for harassment.

# If you found a error, or you want a new feature please dm me on Telegram! t.me/bencewashere

import time
import requests
from random import *
from datetime import datetime
import uuid
import argparse
import hashlib
import sys
import os

parser = argparse.ArgumentParser(prog = 'NGL-Spammer', description='Flooding NGL accounts with questions.')
parser.add_argument("-a", "--account", help="Accounts separated with ','")
parser.add_argument("-q", "--question", help="Separate question(s) with ',' ('hi','what are you doing?')", type=str)
parser.add_argument("-r", "--repeat", help="Number of repetitions (0 = infinite)", type=int)
args = parser.parse_args()

global targetlen, index, i, argisuse, ripetizioni, question_num, question_index, default_quest, question_sent, questions, target, neverhave, haromwords, nevek, tbh, kissmarryblocklist, tizperde, rizzme, confessions, account, id, text_a, question_type, gameslugkuld, kerdesarg, accountarg, last_account, fails
targetlen = 0
index = 0
i = 0
x = 0
argisuse = 0
ripetizioni = 0
question_num = 0
question_index = 0
default_quest = ""
question_sent = []
questions = []
target = []
neverhave = []
haromwords = []
nevek = []
tbh = []
kissmarryblocklist = []
tizperde = []
rizzme = []
confessions = []
account = ""
id = ""
text_a = ""
question_type = ""
gameslugkuld = ""
kerdesarg = ""
accountarg = ""
last_account = ""
fails = 0
request = requests.Session()

def clear():
  if os.name == "nt":
    os.system("cls")
  else:
    os.system("clear")

def letturatarget():
  global target, question_sent, targetlen
  with open("accounts.txt", "r") as targets:
    target = [sorok.strip() for sorok in targets]
    question_sent = [1 for _ in range(len(target))]
    targetlen = len(target)

def exist_account():
  global targetlen, target
  hibak = 0
  hibas = []
  for o in range(targetlen):
    time.sleep(3)
    valasz = requests.get("https://ngl.link/{}".format(target[o]))
    if valasz.status_code == 200:
      print("[OK] -> {} ".format(target[o]))
    else:
      hibak = hibak + 1
      hibas.append(target[o])
      print("[!]  -> {} ".format(target[o]))
  clear()
  accountokStringx = ','.join(target)
  eredmenyx = hashlib.md5(accountokStringx.encode())
  with open("MD5.md5", mode='r+') as md5:
    md5.seek(0)
    md5.write(eredmenyx.hexdigest())
  if hibak > 0:
    print("There's {} accounts that does not exist.".format(hibak))
    print("The accounts are:")
    for g in range (len(hibas)):
      print(hibas[g])
    valasztas = ""
    while valasztas not in ["Y", "N"]:
        valasztas = input("The displayed accounts does not exist. Do you want to remove these? (Y/N): ")
        valasztas = valasztas.upper()
        if valasztas == "Y":
          for g in range (len(hibas)):
            target.remove(hibas[g])
            with open("accounts.txt", "w") as iras:
              iras.write('\n'.join(target))
          print("Deleted!")
          clear()
          accountokStringx = ','.join(target)
          eredmenyx = hashlib.md5(accountokStringx.encode())
          with open("MD5.md5", mode='r+') as md5:
              md5.seek(0) 
              md5.write(eredmenyx.hexdigest())
        elif valasztas == "N":
          print("Your answer is NO, and it is possible that the program returns with a 404 error.")
          accountokStringx = ','.join(target)
          eredmenyx = hashlib.md5(accountokStringx.encode())
          with open("MD5.md5", mode='r+') as md5:
            md5.seek(0) 
            md5.write(eredmenyx.hexdigest())
          time.sleep(5)
          clear()
            
def device_id():
  id = uuid.uuid4().hex
  return "-".join([id[i:i+8] for i in range(0, 32, 8)])

def random_name():
  for k in range(3):
    text_a = (choice(nevek))
    kissmarryblocklist.append(text_a.replace('\n', ''))

device_id()
id = device_id()

def load_questions():
  global questions, default_quest, neverhave, haromwords, nevek, tbh, tizperde, rizzme, confessions
  with open("src/questions.txt", "r", encoding="UTF-8") as targets:
    questions = [sorok.strip() for sorok in targets]
  with open("src/questions.txt", "r", encoding="UTF-8") as targets:
    default_quest = [sorok.strip() for sorok in targets]
  with open("src/neverhave.txt", "r", encoding="UTF-8") as targets:
    neverhave = [sorok.strip() for sorok in targets]
  with open("src/3words.txt", "r", encoding="UTF-8") as targets:
    haromwords = [sorok.strip() for sorok in targets]
  with open("src/names.txt", "r", encoding="UTF-8") as targets:
    nevek = [sorok.strip() for sorok in targets]
  with open("src/tbh.txt", "r", encoding="UTF-8") as targets:
    tbh = [sorok.strip() for sorok in targets]
  with open("src/dealbreaker.txt", "r", encoding="UTF-8") as targets:
    tizperde = [sorok.strip() for sorok in targets]
  with open("src/rizzme.txt", "r", encoding="UTF-8") as targets:
    rizzme = [sorok.strip() for sorok in targets]
  with open("src/confessions.txt", "r", encoding="UTF-8") as targets:
    confessions = [sorok.strip() for sorok in targets]
    
def exist_accountMD():
  global target
  accountokString = ','.join(target)
  eredmeny = hashlib.md5(accountokString.encode())
  if eredmeny.hexdigest() == "346c0131861b4b0811559318a7954187":
    print("The accounts.txt file only contains the example accounts. Please enter the accounts!")
    input("Press enter to exit...")
    sys.exit()
  else:
    with open("MD5.md5", mode='r+') as md5:
      adat = md5.read()
      if adat != eredmeny.hexdigest():
        if adat!= "0":
          print("Checking the accounts.")
          print("If the accounts.txt file has not been changed, this step will be skipped.")
          print("If you want to ensure that the step is always skipped, you can modify the MD5.md5 file to contain the value 0. This will effectively bypass the step regardless if the accounts.txt file has changed.")
          exist_account()
          
if args.account is None:
  argisuse = 0
  letturatarget()
  exist_accountMD()
  load_questions()
else:
  argisuse = 1
  letturatarget()
  accountarg = args.account
  kerdesarg = args.question
  if args.question is None:
    kerdesarg = " "
    load_questions()
  ripetizioni = args.repeat
  if ripetizioni is None:
    ripetizioni = -1
  if ripetizioni == 0:
    ripetizioni = -1
  else:
    ripetizioni = args.repeat

datum = datetime.now()
ido = datum.strftime("%H:%M:%S")
print("NGL Spammer by: BXn4")
print("\n[{}] >> Starting\n".format(ido))
if argisuse > 0:
  target = []
  questions = []
  accountok_split = accountarg.split(',')
  target.extend(accountok_split)
  last_account = target[-1]
  kerdesek_split = kerdesarg.split(',')
  questions.extend(kerdesek_split)
  targetlen = len(target)
  question_num = len(questions)
  question_sent = [1 for _ in range(len(target))]
  targetlen = len(target)
  while x != ripetizioni:
    if i < 10:
      time.sleep(1)
      account = target[index]
      if '/' in account:
        if "rizzme" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Rizzme"
          gameslugkuld = "rizzme"
          if kerdesarg == " ":
            kerdes = (choice(rizzme))
          else:
            kerdes = questions[question_index]
        if "confessions" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Confessions"
          gameslugkuld = "confessions"
          if kerdesarg == " ":
            kerdes = (choice(confessions))
          else:
            kerdes = questions[question_index]
        if "neverhave" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Neverhave"
          gameslugkuld = "neverhave"
          if kerdesarg == " ":
            text_a = ("I've never " + choice(neverhave))
            neverHave = text_a.replace('\n', '')
            kerdes = neverHave
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "crush" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Crush"
          gameslugkuld = "yourcrush"
          if kerdesarg == " ":
            text_a += (choice(nevek))
            crush = text_a.replace('\n', '')
            kerdes = crush
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "wfriendship" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Friendship"
          gameslugkuld = "wfriendship"
          if kerdesarg == " ":
            text_a += (choice(nevek))
            friendship = text_a.replace('\n', '')
            kerdes = friendship
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "shipme" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "Shipme"
          gameslugkuld = "shipme"
          if kerdesarg == " ":
            text_a += (choice(nevek))
            shipme = text_a.replace('\n', '')
            kerdes = shipme
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "tbh" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "TBH"
          gameslugkuld = "tbh"
          if kerdesarg == " ":
            text_a = choice(tbh)
            tbhKuld = text_a.replace('\n', '')
            kerdes = tbhKuld
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "dealbreaker" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "10/10"
          gameslugkuld = "dealbreaker"
          if kerdesarg == " ":
            text_a = choice(tizperde)
            tizperdeKuld = text_a.replace('\n', '')
            kerdes = tizperdeKuld
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "kissmarryblock" in account:
          account_split = account.split("/")[0]
          account = account_split
          question_type = "KMB"
          gameslugkuld = "kissmarryblock"
          if kerdesarg == " ":
            random_name()
            while any(kissmarryblocklist.count(i) > 1 for i in kissmarryblocklist):
              text_a = ""
              kissmarryblocklist = []
              random_name()
            random_name()
            for k in range(3):
              if k == 2:
                text_a += f"{kissmarryblocklist[k]}"
              else:
                text_a += f"{kissmarryblocklist[k]}, "
            kerdes = text_a
            kissmarryblocklist = []
            text_a = ""
          else:
            kerdes = questions[question_index]
        if "3words" in account:
          account_split = account.split("/")[0]
          account = account_split
          gameslugkuld = "3words"
          question_type = "3 Words"
          if kerdesarg == " ":
            text_a += (choice(haromwords) + ", " + choice(haromwords) + ", " + choice(haromwords))
            haromszo = text_a.replace('\n', '')
            kerdes = haromszo
            text_a = ""
          else:
            kerdes = questions[question_index]
      else:
        gameslugkuld = ""
        question_type = "Question"
        if kerdesarg == " ":
          kerdes = (choice(default_quest))
        else:
          kerdes = questions[question_index]
      if question_index == question_num - 1:
        question_index = -1
      url = f"https://ngl.link/{account}"
      question_index += 1

      fejresz = {
        "Referer": url,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0"
        }

      adat = {
        "username": account,
        "question": kerdes,
        "deviceId": id,
        "gameSlug": gameslugkuld,
        "referrer": ""
        }
      
      response = request.post("https://ngl.link/api/subquestion_type", headers=fejresz, data=adat)
      id = device_id()
      if response.status_code == 200:
        fails = 0;
        print("-> %s (%s) \n[%s] %s" % (target[index],question_sent[index],question_type,kerdes) + "\n")
        question_sent[index] += 1
        i = i + 1
      else:
        fails = fails + 1
        if fails < 4:
          print("[{} ({}/3)] Failed! I'll try again after 20 seconds.\n".format(response.status_code,fails))
          time.sleep(20)
        else:
          datum = datetime.now()
          datumido = datum.strftime("%Y-%m-%d")
          ido = datum.strftime("%H:%M")
          with open("logs/{}.txt".format(datumido), mode='a') as logfile:
            logfile.write("{}\nAccount: {}\nError: {} https://www.abstractapi.com/http-status-codes/{}\nNGL: https://ngl.link/{}\n\n".format(ido,account,response.status_code,response.status_code,account))
          print("[!!!] Failed! I continue with the next account.\nThe account is in the: logs/{}.txt file!\n".format(datumido))
          fails = 0;
          i = 10

    if (i == 10):
      id = device_id()
      index += 1
      if index == targetlen:
        index = 0
      datum = datetime.now()
      print("Next: -> " + target[index])
      ido = datum.strftime("%H:%M:%S")
      print("[{}] >> Intermission (2 mins)\n".format(ido))
      time.sleep(120)
      i = 0
      if ripetizioni != -1:
        if account == last_account:
          x += 1
          datum = datetime.now()
          ido = datum.strftime("%H:%M:%S")
          print("[%s] Number of repeats: %s/%s\n" % (ido,x,ripetizioni))
else:
  while True:
    if (i < 10):
      time.sleep(1)
      account = target[index].strip()
      if '/' in account:
        if "rizzme" in account:
          account = account.split("/")[0]
          question_type = "Rizzme"
          gameslugkuld = "rizzme"
          text_a += (choice(rizzme))
          rizzmeKuld = text_a.replace('\n', '')
          kerdes = rizzmeKuld
          text_a = ""
        if "confessions" in account:
          account = account.split("/")[0]
          question_type = "Confessions"
          gameslugkuld = "confessions"
          text_a += (choice(confessions))
          confessionsKuld = text_a.replace('\n', '')
          kerdes = confessionsKuld
          text_a = ""
        if "neverhave" in account:
          account = account.split("/")[0]
          question_type = "Neverhave"
          gameslugkuld = "neverhave"
          text_a = ("I've never " + choice(neverhave))
          neverHave = text_a.replace('\n', '')
          kerdes = neverHave
          text_a = ""
        if "crush" in account:
          account = account.split("/")[0]
          question_type = "Crush"
          gameslugkuld = "yourcrush"
          text_a += (choice(nevek))
          crush = text_a.replace('\n', '')
          kerdes = crush
          text_a = ""
        if "wfriendship" in account:
          account = account.split("/")[0]
          question_type = "Friendship"
          gameslugkuld = "wfriendship"
          text_a += (choice(nevek))
          friendship = text_a.replace('\n', '')
          kerdes = friendship
          text_a = ""
        if "shipme" in account:
          account = account.split("/")[0]
          question_type = "Shipme"
          gameslugkuld = "shipme"
          text_a += (choice(nevek))
          shipme = text_a.replace('\n', '')
          kerdes = shipme
          text_a = ""
        if "tbh" in account:
          account = account.split("/")[0]
          question_type = "TBH"
          gameslugkuld = "tbh"
          text_a = choice(tbh)
          tbhKuld = text_a.replace('\n', '')
          kerdes = tbhKuld
          text_a = ""
        if "dealbreaker" in account:
          account = account.split("/")[0]
          question_type = "10/10"
          gameslugkuld = "dealbreaker"
          text_a = choice(tizperde)
          tizperdeKuld = text_a.replace('\n', '')
          kerdes = tizperdeKuld
          text_a = ""
        if "kissmarryblock" in account:
          account = account.split("/")[0]
          random_name()
          while any(kissmarryblocklist.count(i) > 1 for i in kissmarryblocklist):
            text_a = ""
            kissmarryblocklist = []
            random_name()
          random_name()
          question_type = "KMB"
          gameslugkuld = "kissmarryblock"
          for k in range(3):
            if k == 2:
              text_a += f"{kissmarryblocklist[k]}"
            else:
              text_a += f"{kissmarryblocklist[k]}, "
          kerdes = text_a
          kissmarryblocklist = []
          text_a = ""
        if "3words" in account:
          gameslugkuld = "3words"
          account = account.split("/")[0]
          question_type = "3 Words"
          text_a += (choice(haromwords) + ", " + choice(haromwords) + ", " + choice(haromwords))
          haromszo = text_a.replace('\n', '')
          kerdes = haromszo
          text_a = ""
      else:
        gameslugkuld = ""
        question_type = "Question"
        kerdes = choice(questions)
      url = f"https://ngl.link/{account}"

      fejresz = {
        "Referer": url,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent":
          "Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0"
      }

      adat = {
        "username": account,
        "question": questions,
        "deviceId": id,
        "gameSlug": gameslugkuld,
        "referrer": ""
      }
      response = request.post("https://ngl.link/api/subquestion_type", headers=fejresz, data=adat)
      id = device_id()
      if response.status_code == 200:
        fails = 0;
        print("-> %s (%s) \n[%s] %s" % (target[index],question_sent[index],question_type,kerdes) + "\n")
        question_sent[index] += 1
        i = i + 1
      else:
        fails = fails + 1
        if fails < 4:
          print("[{} ({}/3)] Failed! I'll try again after 20 seconds.\n".format(response.status_code,fails))
          time.sleep(20)
        else:
          datum = datetime.now()
          datumido = datum.strftime("%Y-%m-%d")
          ido = datum.strftime("%H:%M")
          with open("logs/{}.txt".format(datumido), mode='a') as logfile:
            logfile.write("{}\nAccount: {}\nError: {} https://www.abstractapi.com/http-status-codes/{}\nNGL: https://ngl.link/{}\n\n".format(ido,account,response.status_code,response.status_code,account))
          print("[!!!] Failed! I continue with the next account.\nThe account is in the: logs/{}.txt file!\n".format(datumido))
          fails = 0;
          i = 10

    if (i == 10):
      id = device_id()
      index += 1
      if index == targetlen:
        index = 0
      datum = datetime.now()
      print("Next: -> " + target[index])
      ido = datum.strftime("%H:%M:%S")
      print("[{}] >> Intermission (2 mins)\n".format(ido))
      time.sleep(120)
      i = 0

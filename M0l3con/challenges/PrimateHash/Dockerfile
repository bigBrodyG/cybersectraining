FROM ubuntu:latest

RUN apt update
RUN apt install -y python3 python3-dev socat python3-pip gcc g++ make libffi-dev

ADD src/*.py /challenge/
RUN chmod +x /challenge/server.py

ENTRYPOINT socat -d TCP-LISTEN:8000,reuseaddr,fork EXEC:'python3 /challenge/server.py'

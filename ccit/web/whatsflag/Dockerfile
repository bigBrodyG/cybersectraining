FROM python:3

WORKDIR /usr/src/whatsflag

RUN useradd user -rm
USER user

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./main.py" ]
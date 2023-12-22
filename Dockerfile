FROM python:3.11
WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ADD ./handlers ./handlers
ADD ./templates ./templates

ADD ./utils.py ./utils.py
ADD ./onchain.py ./onchain.py
ADD ./main.py ./main.py

CMD [ "python", "main.py" ]

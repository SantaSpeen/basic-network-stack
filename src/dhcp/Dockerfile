FROM python:3.12.6-alpine
LABEL authors="SantaSpeen"

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

ENV IN_DOCKER=1
COPY ./core ./core
COPY ./main.py .

CMD [ "python", "./main.py" ]

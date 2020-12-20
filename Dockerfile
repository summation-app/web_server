FROM python:3.8.1-buster

ENV TZ=America/San_Francisco
ENV DEBIAN_FRONTEND=noninteractive

# pass in build args
ARG ENVIRONMENT
ARG FIREBASE_DATABASE_URL
ARG FIREBASE_APPLICATION_CREDENTIALS_RAW
ARG PYTHON_APP_MODULE=app
# set environment variables to build args
ENV ENVIRONMENT ${ENVIRONMENT}
ENV FIREBASE_DATABASE_URL ${FIREBASE_DATABASE_URL}
ENV FIREBASE_APPLICATION_CREDENTIALS /run/firebase_credentials.json
ENV LOCAL_FILE_STORAGE_PATH /var/lib/summation_web_server
ENV LOCAL_FILE_LOG_PATH /var/log/summation.log
ENV VECTOR_BIN_PATH /run/.vector/bin/vector
ENV PYTHONUNBUFFERED True

RUN apt-get update --fix-missing
RUN apt-get install -y unixodbc-dev

# https://pythonspeed.com/articles/activate-virtualenv-dockerfile/
# Every RUN/CMD line in the Dockerfile is a different process. Running activate in a separate RUN has no effect on future RUN calls; 
WORKDIR /run
ENV VIRTUAL_ENV=/run/env
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /run
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.vector.dev | sh -s -- -y
RUN mkdir /var/lib/vector
RUN chmod 777 /var/lib/vector

RUN mkdir /var/lib/summation_web_server

WORKDIR /run
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py .
COPY db.py .
COPY jwt_verifier.py .

RUN echo ${FIREBASE_APPLICATION_CREDENTIALS_RAW} | base64 -d > firebase_credentials.json

# execute the web app
#ENV UUID=$(cat /proc/sys/kernel/random/uuid)
CMD exec gunicorn -k uvicorn.workers.UvicornWorker --log-level warning --bind :$PORT --workers 1 --threads 8 --timeout 0 ${PYTHON_APP_MODULE}:app
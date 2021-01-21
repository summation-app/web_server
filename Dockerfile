FROM python:3.8.1-buster

ENV TZ=America/San_Francisco
ENV DEBIAN_FRONTEND=noninteractive

# pass in build args
ARG ENVIRONMENT
# set environment variables to build args
ENV ENVIRONMENT ${ENVIRONMENT}
ENV LOCAL_FILE_STORAGE_PATH /var/lib/summation_web_server
ENV LOCAL_FILE_LOG_PATH /var/log/summation.log
ENV VECTOR_BIN_PATH /run/.vector/bin/vector
# for logging
ENV PYTHONUNBUFFERED True

RUN apt-get update --fix-missing
RUN apt-get install -y unixodbc-dev
#RUN apt-get install build-essential libssl-dev libmysqlclient-dev python3-dev

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
COPY logs.py .

# execute the web app
#ENV UUID=$(cat /proc/sys/kernel/random/uuid)
CMD exec gunicorn -k uvicorn.workers.UvicornWorker --log-level warning --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
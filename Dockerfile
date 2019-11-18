FROM python:3.7.5-buster
MAINTAINER William Dockery "wbd220@nyu.edu"
RUN apt-get update -y
RUN apt-get install -y python3-pip
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]

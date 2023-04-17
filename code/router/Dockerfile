FROM python:3.10
RUN ["pip","install","tensorflow"]
COPY  requirements.txt .
RUN ["pip", "install", "-r", "requirements.txt"]
RUN ["mkdir","app"]
COPY . /app
WORKDIR /app
CMD ["python" ,"app.py" ]
EXPOSE 80
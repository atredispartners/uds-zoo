FROM golang:latest

EXPOSE 8888/tcp
ENV DEBIAN_FRONTEND=noninteractive 
WORKDIR /app
COPY . /app
RUN chmod +x ./scripts/run.sh
RUN chmod +x ./scripts/wait-for-it.sh
ENTRYPOINT ["./scripts/run.sh"]

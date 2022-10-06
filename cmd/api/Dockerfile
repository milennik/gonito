FROM golang

RUN mkdir /app

ADD . /app

WORKDIR /app

RUN cd ./cmd/api && go build -o main .

EXPOSE 8080
CMD ["/app/cmd/api/main"]

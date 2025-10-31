ARG PLATFORM=linux/amd64
FROM --platform=$PLATFORM golang:1.25.3

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y sudo nano telnet

# set local time
RUN ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
RUN echo "Asia/Jakarta" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
ARG TZ=Asia/Jakarta
ENV TZ=${TZ}
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# set working dir
RUN mkdir -p /go/src/app
WORKDIR /go/src/app

RUN go install github.com/codegangsta/gin@latest
RUN go install github.com/swaggo/swag/cmd/swag@latest

ARG PORT=5000
ENV PORT=${PORT}
EXPOSE $PORT

CMD ["sh", "-c", "swag init -g main.go && gin -i -a $PORT run main.go"]

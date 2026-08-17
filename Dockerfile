FROM alpine:3.20
RUN apk add --no-cache rsync
COPY . /home/
CMD ["rsync","-aP","/home/","/home/"]

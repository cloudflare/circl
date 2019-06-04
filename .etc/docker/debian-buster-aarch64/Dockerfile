FROM multiarch/debian-debootstrap:arm64-buster

RUN apt-get upgrade -y
RUN apt-get update -qq
USER root
RUN apt-get install -y make wget ca-certificates git
RUN wget https://dl.google.com/go/go1.12.5.linux-arm64.tar.gz
RUN tar -xzf go1.12.5.linux-arm64.tar.gz
RUN mv go /usr/local/
RUN ln -s /usr/local/go/bin/go /usr/bin/
RUN rm -rf /var/lib/apt/lists/* go1.12.5.linux-arm64.tar.gz

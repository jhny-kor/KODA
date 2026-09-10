FROM python:3.12.4
COPY install.sh /usr/local/bin/install.sh
RUN sha256sum -c install.sh.sha256 && sh /usr/local/bin/install.sh
USER nobody

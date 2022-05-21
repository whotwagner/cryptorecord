FROM ruby:3.0

ARG UNAME=rubyapp
ARG UID=1000
ARG GID=1000


RUN groupadd -g $GID -o $UNAME && useradd -u $UID -g $GID -d /app -ms /usr/sbin/nologin $UNAME

WORKDIR /app

COPY scripts/entrypoint.sh /entrypoint.sh

COPY . .
RUN bundle install

VOLUME ["/certs"]

USER $UNAME

ENTRYPOINT ["/entrypoint.sh"]

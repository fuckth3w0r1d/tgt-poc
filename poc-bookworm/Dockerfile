FROM debian:bookworm

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tgt python3 \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/tgt && truncate -s 64M /srv/tgt/disk1

COPY target-init.sh /usr/local/bin/target-init.sh
RUN chmod +x /usr/local/bin/target-init.sh

EXPOSE 3260
CMD ["/usr/local/bin/target-init.sh"]

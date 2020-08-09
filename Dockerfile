FROM python:3.8-alpine

COPY docker/init.sh /init.sh
COPY requirements.txt /app/requirements.txt

RUN apk add --no-cache --virtual .build-deps gcc musl-dev && \
    pip install -r /app/requirements.txt && \
    apk del .build-deps gcc musl-dev && \
    chmod +x /init.sh && \
    apk add --no-cache curl && \
    rm -rf /root/.cache /tmp/* /var/lib/apt/lists/* /var/tmp/*

COPY cfdyndns.py /app/cfdyndns.py

VOLUME ["/opt/config"]

ENTRYPOINT ["/init.sh"]

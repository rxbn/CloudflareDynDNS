#!/usr/bin/env sh

if [ -n "${HEALTHCHECKS_URI}" ]; then
    echo "${CRON_EXPRESSION} python /app/cfdyndns.py -c /opt/config/config.yml && curl -o /dev/null -fsS --retry 3 ${HEALTHCHECKS_URI}" >> /etc/crontabs/root
else
    echo "${CRON_EXPRESSION} python /app/cfdyndns.py -c /opt/config/config.yml" >> /etc/crontabs/root
fi

pid=0

# SIGTERM-handler
term_handler() {
  if [ $pid -ne 0 ]; then
    kill -SIGTERM "$pid"
    wait "$pid"
  fi
  exit 143; # 128 + 15 -- SIGTERM
}

# setup handlers
# on callback, kill the last background process, which is `tail -f /dev/null` and execute the specified handler
trap 'kill ${!}; term_handler' SIGTERM

crond -f -d 9 &
pid="$!"

while true
do
  tail -f /dev/null & wait ${!}
done
#!/usr/bin/env bash
set -eu

echo "Patching wait-for-it not to wait for sim..."

rm -f /tmp/wait_for_sim
mkfifo /tmp/wait_for_sim

echo -e '#!/usr/bin/env bash\nif [[ $1 == "sim:57832" ]]; then\necho "Waiting for tracer..."\ncat /tmp/wait_for_sim\nexit 0\nfi' | cat - /wait-for-it.sh > /tmp/wait-for-it.sh
mv /tmp/wait-for-it.sh /wait-for-it.sh
chmod +x /wait-for-it.sh

echo "Create directories, that would be created using docker volumes"

mkdir -p /certs
mkdir -p /downloads/
mkdir -p /logs/
mkdir -p /logs/qlog
mkdir -p /www

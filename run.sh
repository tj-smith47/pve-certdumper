#!/usr/bin/env bash
# Add the following crontab entry to your PVE host to trigger automatic restarts:
# */1 * * * * /bin/bash -c "if [ -f /etc/pve/ssl/needs-restart ]; then systemctl restart pveproxy; rm /etc/pve/ssl/needs-restart; fi"
#
# OR - Disable by setting DISABLE_PROXY_RESTART: true in your docker-compose.yml

set -e

## Vars
PVE_NEW_CERT_FILE="/output/ssl/pem/${DOMAIN}-public.pem"
PVE_NEW_KEY_FILE="/output/ssl/pem/${DOMAIN}-private.pem"
PVE_CERT_FILE="/output/nodes/${PVE_HOST}/pveproxy-ssl.pem"
PVE_KEY_FILE="/output/nodes/${PVE_HOST}/pveproxy-ssl.key"

## Funcs
dump_certificates() {
  echo "Dumping acme.json to PEM files..."
  bash /dumpcerts.sh "${DNS_RESOLVER}" /traefik/acme.json /output/ssl

  echo -e "\nCertificate Assets:"
  ls -lah /output/ssl/certs/ 2>/dev/null

  echo -e "\nPrivate Assets:"
  ls -lah /output/ssl/private/ 2>/dev/null

  echo -e "\nConverted Assets:"
  ls -lah /output/ssl/pem/ 2>/dev/null

  echo -e "\nConverting certificates from dump..."
  while read -r crt_file; do
    local pem_file
    pem_file=$(echo "${crt_file}" | sed 's/certs/pem/g' | sed 's/.crt/-public.pem/g')

    echo "* openssl x509 -inform PEM -in ${crt_file} > ${pem_file}"
    openssl x509 -inform PEM -in "${crt_file}" >"${pem_file}"
  done < <(ls /output/ssl/certs/*)

  echo -e "\nConverting private keys from dump..."
  while read -r key_file; do
    local pem_file
    pem_file=$(echo "${key_file}" | sed 's/private/pem/g' | sed 's/.key/-private.pem/g')

    echo "* openssl rsa -in ${key_file} -text > ${pem_file}"
    openssl rsa -in "${key_file}" -text >"${pem_file}"
  done < <(ls /output/ssl/private/*)
}

copy_to_proxmox() {
  # Update cert if found
  if [ -f "${PVE_NEW_CERT_FILE}" ]; then
    if ! cmp -s "${PVE_NEW_CERT_FILE}" "${PVE_CERT_FILE}" 2>/dev/null; then
      cp "${PVE_CERT_FILE}" "${PVE_CERT_FILE}.bak"
    fi
    cp "${PVE_NEW_CERT_FILE}" "${PVE_CERT_FILE}"
  fi

  # Update key if found
  if [ -f "${PVE_NEW_KEY_FILE}" ]; then
    if ! cmp -s "${PVE_NEW_KEY_FILE}" "${PVE_KEY_FILE}" 2>/dev/null; then
      cp "${PVE_KEY_FILE}" "${PVE_KEY_FILE}.bak"
    fi
    cp "${PVE_NEW_KEY_FILE}" "${PVE_KEY_FILE}"
  fi

  # Nofify
  if [ -f "${PVE_NEW_CERT_FILE}" ] && [ -f "${PVE_NEW_KEY_FILE}" ]; then
    echo -e "\nUpdated proxy artifacts at /etc/pve/nodes/${PVE_HOST}/pveproxy-ssl.{key,pem} on host ${PVE_HOST}."
    if [ "${DISABLE_PROXY_RESTART}" != "true" ]; then
      echo -e "Notifying host of need to run 'systemctl restart pveproxy'."
      touch /output/ssl/needs-restart
    fi
    echo
  fi
}

## Main
if ! [ -d /output/ssl/pem ]; then
  echo "Generating output dir..."
  mkdir -p /output/ssl/pem
fi

if [ "${BOOTSTRAP}" == "true" ]; then
  echo -e "Running scripts before watch because \$BOOTSTRAP == true.\n"
  dump_certificates
  copy_to_proxmox
fi

while true; do
  inotifywait -e modify /traefik/acme.json
  echo -e "\nChanges Detected! Attempting to update certs...\n"
  dump_certificates
  copy_to_proxmox
done

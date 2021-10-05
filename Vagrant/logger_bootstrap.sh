#! /usr/bin/env bash

# This is the script that is used to provision the logger host

# Override existing DNS Settings using netplan, but don't do it for Terraform AWS builds

download_palantir_osquery_config() {
  if [ -f /opt/osquery-configuration ]; then
    echo "[$(date +%H:%M:%S)]: osquery configs have already been downloaded"
  else
    # Import Palantir osquery configs into Fleet
    echo "[$(date +%H:%M:%S)]: Downloading Palantir osquery configs..."
    cd /opt && git clone https://github.com/palantir/osquery-configuration.git
  fi
}

install_fleet_import_osquery_config() {
  if [ -f "/opt/fleet" ]; then
    echo "[$(date +%H:%M:%S)]: Fleet is already installed"
  else
    cd /opt || exit 1

    echo "[$(date +%H:%M:%S)]: Installing Fleet..."
    if ! grep 'fleet' /etc/hosts; then
      echo -e "\n127.0.0.1       fleet" >>/etc/hosts
    fi
    if ! grep 'logger' /etc/hosts; then
      echo -e "\n127.0.0.1       logger" >>/etc/hosts
    fi

    # Set MySQL username and password, create fleet database
    mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'fleet';"
    mysql -uroot -pfleet -e "create database fleet;"

    # Always download the latest release of Fleet
    curl -s https://api.github.com/repos/fleetdm/fleet/releases | grep 'https://github.com' | grep "/fleet.zip" | cut -d ':' -f 2,3 | tr -d '"' | tr -d ' ' | head -1 | wget --progress=bar:force -i -
    unzip fleet.zip -d fleet
    cp fleet/linux/fleetctl /usr/local/bin/fleetctl && chmod +x /usr/local/bin/fleetctl
    cp fleet/linux/fleet /usr/local/bin/fleet && chmod +x /usr/local/bin/fleet

    # Prepare the DB
    fleet prepare db --mysql_address=127.0.0.1:3306 --mysql_database=fleet --mysql_username=root --mysql_password=fleet

    # Copy over the certs and service file
    cp /vagrant/resources/fleet/server.* /opt/fleet/
    cp /vagrant/resources/fleet/fleet.service /etc/systemd/system/fleet.service

    # Create directory for logs
    mkdir /var/log/fleet

    # Install the service file
    /bin/systemctl enable fleet.service
    /bin/systemctl start fleet.service

    # Start Fleet
    echo "[$(date +%H:%M:%S)]: Waiting for fleet service to start..."
    while true; do
      result=$(curl --silent -k https://127.0.0.1:8412)
      if echo "$result" | grep -q setup; then break; fi
      sleep 1
    done

    fleetctl config set --address https://172.16.20.35:8412
    fleetctl config set --tls-skip-verify true
    fleetctl setup --email admin@purpleteamlab.network --username admin --password 'admin123#' --org-name PurpleteamLab
    fleetctl login --email admin@purpleteamlab.network --password 'admin123#'

    # Set the enrollment secret to match what we deploy to Windows hosts
    mysql -uroot --password=fleet -e 'use fleet; update enroll_secrets set secret = "enrollmentsecret";'
    echo "Updated enrollment secret"

    # Change the query invervals to reflect a lab environment
    # Every hour -> Every 3 minutes
    # Every 24 hours -> Every 15 minutes
    sed -i 's/interval: 3600/interval: 180/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 3600/interval: 180/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 28800/interval: 900/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 28800/interval: 900/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml

    # Don't log osquery INFO messages
    # Fix snapshot event formatting
    fleetctl get options >/tmp/options.yaml
    /usr/bin/yq w -i /tmp/options.yaml 'spec.config.options.enroll_secret' 'enrollmentsecret'
    /usr/bin/yq w -i /tmp/options.yaml 'spec.config.options.logger_snapshot_event_type' 'true'
    fleetctl apply -f /tmp/options.yaml

    # Use fleetctl to import YAML files
    fleetctl apply -f osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    fleetctl apply -f osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    for pack in osquery-configuration/Fleet/Endpoints/packs/*.yaml; do
      fleetctl apply -f "$pack"
    done

    # Add Splunk monitors for Fleet
    # Files must exist before splunk will add a monitor
    touch /var/log/fleet/osquery_result
    touch /var/log/fleet/osquery_status
    /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt
    /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt
  fi
}

install_zeek() {
  echo "[$(date +%H:%M:%S)]: Installing Zeek..."
  # Environment variables
  NODECFG=/opt/zeek/etc/node.cfg
  if ! grep 'zeek' /etc/apt/sources.list.d/security:zeek.list; then
    sh -c "echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/security:zeek.list"
  fi
  wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key -O /tmp/Release.key
  apt-key add - </tmp/Release.key &>/dev/null
  # Update APT repositories
  apt-get -qq -ym update
  # Install tools to build and configure Zeek
  apt-get -qq -ym install zeek crudini
  export PATH=$PATH:/opt/zeek/bin
  pip install zkg==2.1.1
  zkg refresh
  zkg autoconfig
  zkg install --force salesforce/ja3
  # Load Zeek scripts
  echo '
  @load protocols/ftp/software
  @load protocols/smtp/software
  @load protocols/ssh/software
  @load protocols/http/software
  @load tuning/json-logs
  @load policy/integration/collective-intel
  @load policy/frameworks/intel/do_notice
  @load frameworks/intel/seen
  @load frameworks/intel/do_notice
  @load frameworks/files/hash-all-files
  @load base/protocols/smb
  @load policy/protocols/conn/vlan-logging
  @load policy/protocols/conn/mac-logging
  @load ja3
  redef Intel::read_files += {
    "/opt/zeek/etc/intel.dat"
  };
  
  redef ignore_checksums = T;
  
  ' >>/opt/zeek/share/zeek/site/local.zeek

  # Configure Zeek
  crudini --del $NODECFG zeek
  crudini --set $NODECFG manager type manager
  crudini --set $NODECFG manager host localhost
  crudini --set $NODECFG proxy type proxy
  crudini --set $NODECFG proxy host localhost

  # Setup $CPUS numbers of Zeek workers
  # AWS only has a single interface (eth0), so don't monitor eth0 if we're in AWS
  if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
    # TL;DR of ^^^: if you can't reach the AWS metadata service, you're not running in AWS
    # Therefore, it's ok to add this.
    crudini --set $NODECFG worker-eth0 type worker
    crudini --set $NODECFG worker-eth0 host localhost
    crudini --set $NODECFG worker-eth0 interface eth0
    crudini --set $NODECFG worker-eth0 lb_method pf_ring
    crudini --set $NODECFG worker-eth0 lb_procs "$(nproc)"
  fi

  crudini --set $NODECFG worker-eth0 type worker
  crudini --set $NODECFG worker-eth0 host localhost
  crudini --set $NODECFG worker-eth0 interface eth0
  crudini --set $NODECFG worker-eth0 lb_method pf_ring
  crudini --set $NODECFG worker-eth0 lb_procs "$(nproc)"

  # Setup Zeek to run at boot
  cp /vagrant/resources/zeek/zeek.service /lib/systemd/system/zeek.service
  systemctl enable zeek
  systemctl start zeek

  # Configure the Splunk inputs
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && touch /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager index zeek
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager sourcetype zeek:json
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager whitelist '.*\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager blacklist '.*(communication|stderr)\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager disabled 0

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart

  # Verify that Zeek is running
  if ! pgrep -f zeek >/dev/null; then
    echo "Zeek attempted to start but is not running. Exiting"
    exit 1
  fi
}

install_velociraptor() {
  echo "[$(date +%H:%M:%S)]: Installing Velociraptor..."
  if [ ! -d "/opt/velociraptor" ]; then
    mkdir /opt/velociraptor
  fi
  echo "[$(date +%H:%M:%S)]: Attempting to determine the URL for the latest release of Velociraptor"
  LATEST_VELOCIRAPTOR_LINUX_URL=$(curl -sL https://github.com/Velocidex/velociraptor/releases/latest | grep linux-amd64 | grep href | head -1 | cut -d '"' -f 2 | sed 's#^#https://github.com#g')
  echo "[$(date +%H:%M:%S)]: The URL for the latest release was extracted as $LATEST_VELOCIRAPTOR_LINUX_URL"
  echo "[$(date +%H:%M:%S)]: Attempting to download..."
  wget -P /opt/velociraptor --progress=bar:force "$LATEST_VELOCIRAPTOR_LINUX_URL"
  if [ "$(file /opt/velociraptor/velociraptor*linux-amd64 | grep -c 'ELF 64-bit LSB executable')" -eq 1 ]; then
    echo "[$(date +%H:%M:%S)]: Velociraptor successfully downloaded!"
  else
    echo "[$(date +%H:%M:%S)]: Failed to download the latest version of Velociraptor. Please open a DetectionLab issue on Github."
    return
  fi

  cd /opt/velociraptor || exit 1
  mv velociraptor-*-linux-amd64 velociraptor
  chmod +x velociraptor
  cp /vagrant/resources/velociraptor/server.config.yaml /opt/velociraptor
  echo "[$(date +%H:%M:%S)]: Creating Velociraptor dpkg..."
  ./velociraptor --config /opt/velociraptor/server.config.yaml debian server
  echo "[$(date +%H:%M:%S)]: Installing the dpkg..."
  if dpkg -i velociraptor_*_server.deb >/dev/null; then
    echo "[$(date +%H:%M:%S)]: Installation complete!"
  else
    echo "[$(date +%H:%M:%S)]: Failed to install the dpkg"
    return
  fi
}

install_suricata() {
  # Run iwr -Uri testmyids.com -UserAgent "BlackSun" in Powershell to generate test alerts from Windows
  echo "[$(date +%H:%M:%S)]: Installing Suricata..."

  # Install suricata
  apt-get -qq -y install suricata crudini
  test_suricata_prerequisites
  # Install suricata-update
  cd /opt || exit 1
  git clone https://github.com/OISF/suricata-update.git
  cd /opt/suricata-update || exit 1
  pip install pyyaml
  python setup.py install

  cp /vagrant/resources/suricata/suricata.yaml /etc/suricata/suricata.yaml
  crudini --set --format=sh /etc/default/suricata '' iface eth0
  # update suricata signature sources
  suricata-update update-sources
  # disable protocol decode as it is duplicative of Zeek
  echo re:protocol-command-decode >>/etc/suricata/disable.conf
  # enable et-open and attackdetection sources
  suricata-update enable-source et/open
  suricata-update enable-source ptresearch/attackdetection

  # Configure the Splunk inputs
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json'
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0
  crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0

  # Update suricata and restart
  suricata-update
  service suricata stop
  service suricata start
  sleep 3

  # Verify that Suricata is running
  if ! pgrep -f suricata >/dev/null; then
    echo "Suricata attempted to start but is not running. Exiting"
    exit 1
  fi

  # Configure a logrotate policy for Suricata
  cat >/etc/logrotate.d/suricata <<EOF
/var/log/suricata/*.log /var/log/suricata/*.json
{
    hourly
    rotate 0
    missingok
    nocompress
    size=500M
    sharedscripts
    postrotate
            /bin/kill -HUP \`cat /var/run/suricata.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF

}

test_suricata_prerequisites() {
  for package in suricata crudini; do
    echo "[$(date +%H:%M:%S)]: [TEST] Validating that $package is correctly installed..."
    # Loop through each package using dpkg
    if ! dpkg -S $package >/dev/null; then
      # If which returns a non-zero return code, try to re-install the package
      echo "[-] $package was not found. Attempting to reinstall."
      apt-get clean && apt-get -qq update && apt-get install -y $package
      if ! which $package >/dev/null; then
        # If the reinstall fails, give up
        echo "[X] Unable to install $package even after a retry. Exiting."
        exit 1
      fi
    else
      echo "[+] $package was successfully installed!"
    fi
  done
}

install_guacamole() {
  echo "[$(date +%H:%M:%S)]: Installing Guacamole..."
  cd /opt || exit 1
  apt-get -qq install -y libcairo2-dev libjpeg62-dev libpng-dev libossp-uuid-dev libfreerdp-dev libpango1.0-dev libssh2-1-dev libssh-dev tomcat8 tomcat8-admin tomcat8-user
  wget --progress=bar:force "http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/1.0.0/source/guacamole-server-1.0.0.tar.gz" -O guacamole-server-1.0.0.tar.gz
  tar -xf guacamole-server-1.0.0.tar.gz && cd guacamole-server-1.0.0 || echo "[-] Unable to find the Guacamole folder."
  ./configure &>/dev/null && make --quiet &>/dev/null && make --quiet install &>/dev/null || echo "[-] An error occurred while installing Guacamole."
  ldconfig
  cd /var/lib/tomcat8/webapps || echo "[-] Unable to find the tomcat8/webapps folder."
  wget --progress=bar:force "http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/1.0.0/binary/guacamole-1.0.0.war" -O guacamole.war
  mkdir /etc/guacamole
  mkdir /etc/guacamole/shares
  sudo chmod 777 /etc/guacamole/shares
  mkdir /usr/share/tomcat8/.guacamole
  cp /vagrant/resources/guacamole/user-mapping.xml /etc/guacamole/
  cp /vagrant/resources/guacamole/guacamole.properties /etc/guacamole/
  cp /vagrant/resources/guacamole/guacd.service /lib/systemd/system
  sudo ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat8/.guacamole/
  sudo ln -s /etc/guacamole/user-mapping.xml /usr/share/tomcat8/.guacamole/
  sudo ln -s /usr/local/lib/freerdp /usr/lib/x86_64-linux-gnu/
  systemctl enable guacd
  systemctl enable tomcat8
  systemctl start guacd
  systemctl start tomcat8
}

postinstall_tasks() {
  # Include Splunk and Zeek in the PATH
  echo export PATH="$PATH:/opt/splunk/bin:/opt/zeek/bin" >>~/.bashrc
  echo "export SPLUNK_HOME=/opt/splunk" >>~/.bashrc
  # Ping DetectionLab server for usage statistics
  curl -s -A "DetectionLab-logger" "https:/ping.detectionlab.network/logger" || echo "Unable to connect to ping.detectionlab.network"
}

configure_splunk_inputs() {
  # Suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json'
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0
  crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0

  # Fleet
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt

  # Zeek
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && touch /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager index zeek
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager sourcetype zeek:json
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager whitelist '.*\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager blacklist '.*(communication|stderr)\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager disabled 0

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart
}

main() {
  apt_install_prerequisites
  modify_motd
  test_prerequisites
  fix_eth0_static_ip
  install_splunk
  download_palantir_osquery_config
  install_fleet_import_osquery_config
  install_velociraptor
  install_suricata
  install_zeek
  install_guacamole
  postinstall_tasks
}

splunk_only() {
  install_splunk
  configure_splunk_inputs
}

# Allow custom modes via CLI args
if [ -n "$1" ]; then
  eval "$1"
else
  main
fi
exit 0

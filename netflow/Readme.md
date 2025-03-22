# NetFlow Collector and Analyzer Service Setup

This documentation provides instructions on setting up and managing the NetFlow Collector and Analyzer services using `systemd`.

## Prerequisites
Ensure you have:
- Python 3 installed (`/usr/bin/python3`)
- Systemd installed and running
- Necessary permissions to create and manage services

## Service Files

### NetFlow Collector Service
#### File: `/etc/systemd/system/netflow-collector.service`
```ini
[Unit]
Description=NetFlow Collector Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/netflow_collect/netflow/collector.py --host 0.0.0.0 --port 9995 --output-dir /var/log/
WorkingDirectory=/var/netflow_collect/netflow/
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

### NetFlow Analyzer Service
#### File: `/etc/systemd/system/netflow-analyzer.service`
```ini
[Unit]
Description=NetFlow Analyzer Daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/netflow_collect/netflow/analyzer.py -f /var/log/netflow.json -o /var/log/netflow_host.json --dns-servers 8.8.8.8 8.8.4.4
Restart=always
User=root
WorkingDirectory=/var/netflow_collect/netflow
StandardOutput=append:/var/log/netflow_analyzer.log
StandardError=append:/var/log/netflow_analyzer_error.log

[Install]
WantedBy=multi-user.target
```

## Setting Up the Services

### 1. Create and Edit Service Files
Save the above configurations to the respective service files in `/etc/systemd/system/`.

### 2. Reload `systemd`
```bash
sudo systemctl daemon-reload
```

### 3. Enable the Services (Start on Boot)
```bash
sudo systemctl enable netflow-collector
sudo systemctl enable netflow-analyzer
```

### 4. Start the Services
```bash
sudo systemctl start netflow-collector
sudo systemctl start netflow-analyzer
```

### 5. Check Service Status
```bash
sudo systemctl status netflow-collector
sudo systemctl status netflow-analyzer
```

## Managing the Services

### Restart Services
```bash
sudo systemctl restart netflow-collector
sudo systemctl restart netflow-analyzer
```

### Stop Services
```bash
sudo systemctl stop netflow-collector
sudo systemctl stop netflow-analyzer
```

### View Logs
#### Using `journalctl`
```bash
sudo journalctl -u netflow-collector --follow
sudo journalctl -u netflow-analyzer --follow
```

#### Viewing Log Files
```bash
tail -f /var/log/netflow_analyzer.log
tail -f /var/log/netflow_analyzer_error.log
```

## Troubleshooting
- If a service fails to start, check logs using:
  ```bash
  sudo journalctl -u netflow-collector -n 50 --no-pager
  sudo journalctl -u netflow-analyzer -n 50 --no-pager
  ```
- Ensure the scripts have the correct permissions:
  ```bash
  sudo chmod +x /var/netflow_collect/netflow/collector.py
  sudo chmod +x /var/netflow_collect/netflow/analyzer.py
  ```
- Verify Python dependencies:
  ```bash
  python3 -m pip install -r /var/netflow_collect/netflow/requirements.txt
  ```

## Uninstalling the Services
```bash
sudo systemctl stop netflow-collector
sudo systemctl stop netflow-analyzer
sudo systemctl disable netflow-collector
sudo systemctl disable netflow-analyzer
sudo rm /etc/systemd/system/netflow-collector.service
sudo rm /etc/systemd/system/netflow-analyzer.service
sudo systemctl daemon-reload
```

## Conclusion
This guide provides steps to configure, run, and manage the NetFlow Collector and Analyzer services using `systemd`. If you encounter any issues, refer to the troubleshooting section.


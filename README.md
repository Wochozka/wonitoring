# wonitoring

## ⚠️ Configuration Required

Before running this network monitoring script, please make sure to configure the following:

### 1. **Pushover API Credentials**
You must provide your own [Pushover](https://pushover.net/) credentials:

- `PUSHOVER_USER_KEY`
- `PUSHOVER_API_TOKEN`

These should be set in your environment variables or directly in your configuration, depending on how the script is set up.

---

### 2. **Monitoring Targets**
Define your own monitoring targets in either:

- `device.json`  
- `device.yaml`

These files should contain the list of devices or IP addresses to monitor, along with any other necessary metadata (e.g., name, ping interval, threshold).

> **Tip:** Only one of these files will be used, depending on what you configure in `network_monitoring.py`.

---

### 3. **Configuration Path (Optional)**
If you want to use a custom configuration file, edit the path in the script:

```python
DEFAULT_CONFIG_FILE = "device.yaml"  # or "device.json"
```

Set it to the file that contains your own monitoring configuration.

Without these configurations, the script will not function properly. Make sure to adjust them before running.

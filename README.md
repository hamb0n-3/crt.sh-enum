# crt.sh-enum

Pulls certificate-transparency records from [crt.sh](https://crt.sh) to enumerate
subdomains for a domain. Threaded, with retries; writes CSV and JSON to `reports/`.

`--enum` mode expands each target with a built-in keyword list (dev, staging,
admin, api, vpn, …) to surface hosts that a plain query misses.

## Usage

```
# straight lookup
python crt.sh-enum.py -q example.com

# keyword-expanded enumeration
python crt.sh-enum.py -e -t example.com
```

`-q/--query` and `-t/--target` can be repeated. Other flags: `--out-dir`,
`--workers`, `--no-json`, `--no-csv`, `--no-expired`, `--log-level`.

\# cert-tools



A Python script that scans a folder of X.509 certificates and reports, for each one:

subject, issuer, expiry date, days left, whether it is a CA, and its Extended Key Usage.

It flags certificates that are expired or expire within a chosen number of days.



\## Usage



```

pip install -r requirements.txt

python cert\_report.py <folder> \[--days N] \[--csv report.csv]

```



\- `--days N` - warn when a certificate expires within N days (default 30)

\- `--csv FILE` - also save the report as a CSV file (opens in Excel)



The script exits with code \*\*1\*\* if any certificate is expired or expiring, so it can be used in scheduled tasks or other scripts.



\## Example



Run against my \[pki-lab-openssl](https://github.com/besnikemini5/pki-lab-openssl) certificates:



```

STATUS     DAYS  EXPIRES     CA   EKU           SUBJECT

OK          364  2027-10-19  no   serverAuth    CN=server

OK          364  2027-10-19  no   clientAuth    CN=user

OK         1824  2031-10-18  yes  -             CN=Besnik Lab Issuing CA

OK         3649  2036-10-16  yes  -             CN=Besnik Lab Root CA



4 certificates checked, 0 expired or expiring within 30 days

```


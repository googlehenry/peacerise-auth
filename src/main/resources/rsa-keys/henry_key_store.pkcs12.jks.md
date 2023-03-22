keytool -genkeypair -alias henry_key_pair_2003_03_17 -keyalg RSA -keystore henry_key_store.pkcs12.jks -storepass 123test321 -keypass 123test321 -storetype PKCS12
keytool -list -keystore henry_key_store.pkcs12.jks -storepass 123test321
keytool -export -keystore henry_key_store.pkcs12.jks -alias henry_key_pair_2003_03_17 -file henry_key_pair_2003_03_17_public_key.cer
keytool -list -rfc --keystore henry_key_store.pkcs12.jks | openssl x509 -inform pem -pubkey


keytool -genkeypair -alias henry_key_pair_2003_03_22 -keyalg RSA -keystore henry_key_store.pkcs12.jks -storepass 123test321 -keypass 321test123 -storetype PKCS12
keytool -list -keystore henry_key_store.pkcs12.jks -storepass 123test321
keytool -export -keystore henry_key_store.pkcs12.jks -alias henry_key_pair_2003_03_22 -file henry_key_pair_2003_03_22_public_key.cer
keytool -list -rfc --keystore henry_key_store.pkcs12.jks | openssl x509 -inform pem -pubkey


```
$ keytool -list -rfc --keystore henry_key_store.pkcs12.jks
Enter keystore password:
Keystore type: PKCS12
Keystore provider: SunJSSE

Your keystore contains 2 entries

Alias name: henry_key_pair_2003_03_17
Creation date: Mar 17, 2023
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIEFAb4KDANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJj
bjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnNoMQ4wDAYDVQQKEwVoZW5yeTEOMAwG
A1UECxMFaGVucnkxDjAMBgNVBAMTBWhlbnJ5MB4XDTIzMDMxNzAwMzAyNVoXDTIz
MDYxNTAwMzAyNVowVzELMAkGA1UEBhMCY24xCzAJBgNVBAgTAnNoMQswCQYDVQQH
EwJzaDEOMAwGA1UEChMFaGVucnkxDjAMBgNVBAsTBWhlbnJ5MQ4wDAYDVQQDEwVo
ZW5yeTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANXZcu26XrhpQi7f
ICXVh7q0lDBcTzz6mTyl75pWucOZXmS2vd8ZEA8RkXQZVnszQgiarkarKqUE4GLR
X3QF+RBZRRzNLKtW6J7ZDBscIUVL+L2CrQBk+46fnr/iU2ZtCa+OQZQdbIzmwM97
nt0v1GqmXtn2Me+ZVZMpBvzCLxH9O3BlCUStJ+5cNvvg8CRpf6forRaUHwZyjHux
tajcDus/N636LxTNYzxulPh3b38a2Z9eN6dAzoU50ZtMry4hmEimwB4oCPpMc7Wc
S9bKIhOAt8jIsG9jQzMPnMsr7mT3/poR9QRZkl3WMH+KpZnHWVuFJzns2P09r4q2
csqsfB8CAwEAAaMhMB8wHQYDVR0OBBYEFDFiMWhgrePynPdY1MeBNxAAehOkMA0G
CSqGSIb3DQEBCwUAA4IBAQAuDLB+BSB5w04rlxT01Quqp3xtQaznqbU2C05fZ+zf
eyKZXw+W6Jjnau64AgJ4mWGTHRPhM5krJMRfOM3dnpcgWdyYnVXtf5ysUjfbXq+R
CWNND31KeSIZJNnKAADdOY8N38RBZ19qIR1f6/aUXS4ck3yvXJ+d+Drlr42mMU62
mvDNxR/S/WAToxeQGvNlbuqMXXwdS7/1xsRNY3lqJjvXFHjLIyzC3hSYaID+XEd1
pq+Drp10Oidi4o8vzi4ImcW2b6xe7DD6KY700kbKJ56yRrfuhO5WtDqxSh3Fa+Xr
f/pn1q0W9pRo4B0RQSNT1mcNmsxP9JgqKPrYndCkiGKa
-----END CERTIFICATE-----


*******************************************
*******************************************


Alias name: henry_key_pair_2003_03_22
Creation date: Mar 22, 2023
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIEPGXgBjANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJj
bjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnNoMQ4wDAYDVQQKEwVhbGljZTEOMAwG
A1UECxMFYWxpY2UxDjAMBgNVBAMTBWFsaWNlMB4XDTIzMDMyMjAxMTk0OFoXDTIz
MDYyMDAxMTk0OFowVzELMAkGA1UEBhMCY24xCzAJBgNVBAgTAnNoMQswCQYDVQQH
EwJzaDEOMAwGA1UEChMFYWxpY2UxDjAMBgNVBAsTBWFsaWNlMQ4wDAYDVQQDEwVh
bGljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPl5Tigh7y9qQ9Vw
sAJi+ZFF8xuK2huEo/2UvdUz6lczf+VsIu/KAemy1qjeV3uC1sGFp7bSjJmgmnHk
7YVqoxXef4xs5zKdMSEwbnMKbPMIxDnsu8KlJzKZCL2DqSglgnveq2fKOFaoj1Jm
YDAOuhNYcAHSuiKTkhwOG80kV/fVByG7+aSKRGNHOuCZYN5vRgvQZ4RBmN9IcYRb
LShsOnLubRsWcqcuclzXKwKhdFnH3Qi6/6F0OqLEG/Fk0GWhoohcqrm8q+Mi7mZ9
chqC+hDLFXbPVvwAQJZMxjlaFtmWEldTxNu9n6mG99qjwWIaeU6BtOFRIKMVxsG1
CbO/iK8CAwEAAaMhMB8wHQYDVR0OBBYEFIeRr2pvm6S/hzHecg9YPcYYrk6LMA0G
CSqGSIb3DQEBCwUAA4IBAQDanDWbIUnWN8xP4kQ5nMlgnyOOEUiDA4YjjG9KKZxO
dy5LniXMM2aQE0Vu4y81Es2+9QhO2Yyl9QgCMiLFQ1+eiwFSXnN0y4/McnTf/zCe
uX23TH/aUczu1tY7eHtU4yegLHG4fBrQ6kMAUHgVk49iL+FDCyNC5viM5zKfUkhp
03W6o6LlQIOrctttk3hmp58Aev2ACr37iqETUoXMNaGuMsQDsJiLDZ6XQs03AND6
bPlUgs4BZSitRRgMCSA7LmPBbuomgefUEM9DqLCNDi5OlvHsCuduUYhIiyL+y+9o
iF6bVHpxS9OO2VD+CTSI/fcrjgmTyaiAskXrqCzD8RUJ
-----END CERTIFICATE-----


*******************************************
*******************************************
```
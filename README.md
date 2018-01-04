Design Overview
===============

VSSM is a virtualized software security module. It is meant to replicate many features of a hardware security module, but with features that make it better suited to cloud deployments.

VSSM has the following properties:

* An API for standard cryptographic operations: symmetric and asymmetric encryption/decryption, asymmetric sign/verify, and HMAC create/verify.
* Non-exportable secrets. That is, there is no API for exporting key material used in the above operations. Thus, as with an HSM, it is impossible for even administrative operators to extract key material. (Note that )
* Auto-scalable architecture. VSSM uses a cloud-provider mechanism for attestation so that existing instances of VSSM can supply key material to new instances.

When an instance of VSSM first comes online, it needs to bootstrap itself. This can be one in one of two ways.

1. If it is not the first instance, the service will discover other instances and use the cloud-provider attestation mechanism to get the RPC certificate private key from another instance.
2. If it is the first instance, an operator needs to manually supply a bootstrap secret. This secret can then been discarded (in which case it is truely impossible for operators to ever extract key material from VSSM). However, you would more likely want to keep an offline copy of this secret (e.g. in a secure, offline physical vault) so that VSSM can be bootstrapped again in a disaster scenario where all instances have been lost or in the event that VSSM needs to be updated.

Either way, once an instance comes online it will then securely synchronize the VSSM keystore from any other instances.

Synchronization
---------------

VSSM is designed to be run in a distributed, elastic environment. Therefore it performs synchronization will all other nodes in the cluster whenever key material is generated/injected or when a node first comes online. Furthermore, nodes periodically poll other nodes in the cluster for synchronization updates in case any updates have been lost. 

Trust Model
===========

A primary goal of this application is to make keys non-exportable, similar to an HSM appliance. However, we still need to provide some kind of export mechanism for two purposes. First, nodes need to be able to synchronize state; the provides a mechanusm where injected keys can be shared across all instances. Further, it provides a way for an instance to bootstrap itself from other instances. Secondly, we want to provide a means to create backups of the key inventory in an encrypted form so that keys can be restored in case that all VSSM instances are lost.

To achieve this, key inventory can be exported using some APIs, but when this is done the inventory is protected using the RPC certificate private key. This key is a shared secret amongst VSSM instances, so all instances can use it to synchronize state, bootstrap key inventory, and restore from backups.

This key can come from one of two places, which means these must be parties that you implicitly trust with your key inventory. *If you do not trust these parties, VSSM is not appropriate for your infrastructure.*

1. The operator which first sets up your VSSM cluster. The first instance must be manually bootstrapped with a key, uploaded by an operator. The operator has an opportunity to make an offline backup of this key. (In fact, this is recommended so that you can recover key inventories from backup.) Since this key can be used to decrypt a key inventory export, the holder of this key has implicit access to any future key inventory.
2. The cloud provider, which has key material used for attestation. Since the auto-scalability of VSSM's design relies on instances being able to attest their identity to other instances, the ability to spoof this attestation would allow a malicious party to access the RPC certificate private key and therefore decrypt key inventory. Since your cloud provider has access to the key material necessary to perform attestation, it implicity has the means to spoof this attestation.

We note that in the context of using a software-based security solution, we are already implicitly trusting our cloud provider. Even without spoofing attestation credentials, the cloud provider also runs the hypervisor in which our VSSM instances are running. Therefore the cloud provider has direct access to memory where plaintext key material lives. Therefore, trust in the cloud provider should already be implicit. If you do not trust your cloud provider, then a hardware-backed security system is necessary and VSSM is not appropriate for your use case.

Other Caveats
=============

This security module solution is not a drop-in replacement for HSMs. Take note of the following concerns:

* VSSM is not designed to be defensive against cryptographic side channels. It uses golang's cryptography SDK. To the extent that this SDK contains a side channels (such as timing analysis), VSSM will be subject to these attacks as well.
* VSSM has not had any professional, third-party audit. It does not necessarily comply with any certifications.

API Overview
============

During manual bootstrap, an API is made available on port 8080. This API accepts a single type of request for bootstrapping the service.

After the bootstrap phase, VSSM sets up four API ports.

1. The primary port is 8080, which has general-use endpoints (e.g. for performing encrypt/decrypt operations) as well as administrative endpoints (e.g. for injecting new keys). This port requires mutual TLS connections.

2. A second service is on 8081. This is a plaintext endpoint that is just used for simple HTTP-based healthchecks.

3. A third service is setup on port 8082. This endpoint uses mutual TLS and is only used internally by VSSM, e.g. for synchronizing key material. These endpoints are therefore not documented below. However, it is noted here so that security rules can be setup that allow instances of VSSM to make requests to other instances of VSSM on this port.

4. A fourth service is setup on port 8083. This is also an internal service port used for automatic bootstrapping of new instances. It uses server-only TLS since new instances don't have a client secret for mutual TLS. However, the only API it serves requires authentication using cloud-provider attestation.


API Specification
=================

VSSM has a REST-like API served over HTTP. All endpoints only accept POST requests, accept only `application/json` media types, and only respond with `application/json` responses.

The format of the request and response messages are defined by [vssm.proto](vssm.proto), with messages serialized by the protobuf-JSON specification.

For example:

    curl --cacert server.pem --cert client.pem --key cert.key -d \
        '{"input":"AAAA", "keyName":"foo", "algorithm": "AES/GCM/NoPadding"}' \
        https://VSSM:8080/REST/v1/symmetric/encrypt
        
        {"output":"+HSZ06VNXhUDLTFnXRFTZWviNRNozt0bkBIa8gVXsA=="}

The following endpoints correspond to the VssmService methods defined in [vssm.proto](vssm.proto).

| ----------------- | --------------------------- |
| SymmetricEncrypt  | /REST/v1/symmetric/encrypt  |
| SymmetricDecrypt  | /REST/v1/symmetric/decrypt  |
| AsymmetricEncrypt | /REST/v1/asymmetric/encrypt |
| AsymmetricDecrypt | /REST/v1/asymmetric/decrypt |
| AsymmetricSign    | /REST/v1/asymmetric/sign    |
| AsymmetricVerify  | /REST/v1/asymmetric/verify  |
| HmacCreate        | /REST/v1/hmac/create        |
| HmacVerify        | /REST/v1/hmac/verify        |

The following endpoints correspond to the AdminService methods defined in [vssm.proto](vssm.proto).

| -------------- | ----------------------------- |
| GenerateKey    | /REST/v1/admin/generatekey    |
| InjectKey      | /REST/v1/admin/injectkey      |
| GenerateBackup | /REST/v1/admin/generatebackup |
| RestoreBackup  | /REST/v1/admin/restorebackup  |
| ListKeys       | /REST/v1/admin/listkeys       |
| GetLogs        | /REST/v1/admin/getlogs        |

Operator's Guide
================

Configuration
-------------

A deployment of VSSM requires a few configuration properties to be set. These properties are read from a JSON configuration file. VSSM will look in the working directory for `config.json`. If it does not exist, it will look for it in `/etc/vssm/config.json`. If neither exists, it will fail to start.

The configuration needs three properties set:

1. **`rpcCertificate`**: The base64-encoded DER bytes of the X.509 certificate to be used by VSSM. This used for both server and client authentication during internal VSSM RPC calls (e.g. for synchronization), so the X.509 certificate used must satisfy a few properties. See the notes below for how you can generate a valid certificate for use:

    1. The certificate must have VSSM as a subject name, i.e. in the subject CN or in a DNS SAN.
    
    2. If the key usage extension is specified, it must allow both client and server authentication.

2. **`clientTrustStore`**: An array of base64-encoded DER bytes of the X.509 certificates forming the truststore that the VSSM service will use to authenticate clients. In other words, this should contain the CAs under which clients of VSSM will have their certificates minted.

3. **`rootPassword`**: A encoded scrypt hash of the administrator password that will be used for any administrative operations. You can calculate the hash of a password with the necessary encoding by using the `scrypt.bin` executable produced when running `make scrypt.bin`. 

The following is an example `config.json`:

    {
       "rpcCertificate": "MIIDHDCCAgSgAwIBAgIJAMj7+1Qg5XfgMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFZTU00wHhcNMTcxMDA1MDc0ODAxWhcNMjcxMDAzMDc0ODAxWjAPMQ0wCwYDVQQDDARWU1NNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4bIvezCNwtOVYgmZe60ScYaO0m1h42Lf4vPgnSqhww1buGvGsYD9mzqmP3prH2f37x9t1Xf9jcHPj1qSfJfQx1EHzOgp+dHZaD8TrvG9YETTcSl1eCrPhkKytjXRW/1J1xsYwoTU7aZaa0bGx9tMkpi4/mzqV5p5FdE1D+W2of5rp+HjMxLMQKnNWXxC3nyoCDvQ+wPbolB/6fCBFoytbh3wLK86r6BoBIkRUdFQavle0aohUOurwxtT6ED+WpkZDxfdXhTC5Dl9TBPURusuyAKX5aoSB8i/62WKYZOwInv/e0fKyQDTk6I6N+k6pqz4JK7QLw0ImBQRMGUBw6gAQIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUuFKBP9vTvIOsjYGwyiJx+agOVuUwHwYDVR0jBBgwFoAUuFKBP9vTvIOsjYGwyiJx+agOVuUwDQYJKoZIhvcNAQELBQADggEBAEzBBgtlWAaQEkvweQpK+OpMrykJR2kcx/KIW6csbHPG/KotyvmQEf/Xf98y8SXNuLwRIhHQozEcJ8Dg5t6qcOWGYQNAJHwR8vyV49DI9GchvsU9So7LMezTfDWiGLr7rGdqvwLLB38FK2HC/vhgob1vE/Mg1VgdhbAorF5ZffkARIZRq3/R/TQCpKk9nhkFivvKqZXYserO+d1hxVviytQpBzoeCS4DCIMkerWCPYLfjBOplKUAJR9ItHg4I7fk0fPFYX05myW6qc72PbHG8lBIEvONEL4DZkkoWkvTDfh4v9F0jYkWuka608xBxDswO9YocsV6DM/qDbBidQ+h2/Q=",
       "clientTrustStore": ["MIIDCDCCAfCgAwIBAgIJAIJfbYywnj9MMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDlZTU00gQ2xpZW50IENBMB4XDTE3MTAwNTA3MTEwNFoXDTI3MTAwMzA3MTEwNFowGTEXMBUGA1UEAwwOVlNTTSBDbGllbnQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbe18ii0j9mPNh3vzMOTD/mLMH+Vl9pgId6pJ5TxeHAHVwWEW3SqOZOIFpzGuxz/k+v2lFDKF+I2+9N9JyQ0LKlnTGV8slLVWainQ4JZWBH44RBmDGsUzjxJvNqTzCEp/OTGFdWsmxojyuGkJHDpom191iW12Gzo3zyBDa54UXQUqLmsnW9dXsKCK5Bf9+37TUpjWGDwrmYR7iEKZrcBzBBkkFVAYy+GO79T5ZRKnW/BiZclFkpfbRLdOigPyOmNubw+BoUFlHOBm/4EEYFQJU62ccK76v93u5eNC7rQRyHAwtwBeLvivNO2xi5LNgrQTjYY/AgExkQWwUUS6Sab+pAgMBAAGjUzBRMB0GA1UdDgQWBBTrpsI87UPSF6SIs1thinxuakygCTAfBgNVHSMEGDAWgBTrpsI87UPSF6SIs1thinxuakygCTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBCwxPfjHX+1vfd4t1tnlGR4CirdtS5QX6ShBoFVLFJz8y2AKtzjDvg/cDAW+UbWyipIsozCd7YXP1AoeAn+VzG1QWVmrxyJ2iooPR16DNZ24DtiZcdTo7vHAzVRxQ5z/2HzIpwrrKEGDMZ+I42GLFwWSWkP9yczC/sONzfiMWJoFk4w4r+lRro84S7vP/yjemURMP46Ksfz9e9DigqOTtBvy9+3My6CEjJhPsgc6uCk0GatNWGSgTG7+BJH+Ol265W4PoAkbu3qIm2KRf0JfgVtWbdtZHFX2tqtvkn9OtTKv1B8ql4sE7o5p/zqJ7hCIPmMNdA+04Ekti4ogZ3IzQd"],
       "rootPassword": "$s0$F0801$XHElFk20jS6fT4yNPCLuFw==$tKUB+oOGEZV3TQSMz8qgHACzavObaS8KFby+VA9IAn8="
    }
    
Manual Bootstrapping
--------------------

While VSSM is designed to autoscale by using attestation to bring up new nodes, the first node in a cluster must be manually bootstrapped. Bootstrapping is done by sending the private key (in base64-encoded PKCS8 DER format) associated with the `rpcCertificate` provided in `config.json`. For example:

    curl -k --cert client.pem --key client.key -d '{"rpcPrivateKey":"MIIE..."}' https://192.168.0.100:8080/REST/v1/admin/bootstrap

Note that when doing this, since the initial server has no secret material it cannot present any form of trusted certificate. Therefore the certificate presented will be a runtime-generated self-signed certificate. Since you must therefore execute this bootstrapping without verifying the server, an active adversary could intercept the bootstrap message and subsequently extract all key material from VSSM. Thus it is critical that you execute manual bootstrapping in an implicitly trusted network environment. See the section below on secure bootstrapping for tips.

Generating Certificates
-----------------------

To generate a CA to be used for client certificates and a certificate under that CA:

    openssl req -new -x509 -days 3650 -extensions v3_ca -keyout cakey.pem -out cacert.pem -nodes -subj '/CN=VSSM Client CA/'
    openssl req -new -keyout client.key -out client.csr -subj '/CN=VSSM Client/' -nodes
    openssl x509 -req -CA cacert.pem -CAkey cakey.pem -set_serial 1 -in client.csr -out client.pem -days 365 

To get the encoded version of `cacert.pem` for use in `config.json` you can run

    openssl x509 -in cacert.pem -outform DER | openssl base64 -A
    
To generate a self-signed certificate for use by VSSM you can run

    openssl req -new -x509 -days 3650 -extensions usr_cert -keyout server.key -out server.pem -nodes -subj '/CN=VSSM/'


Secure Deployment
=================

TODO 

Secure Manual Bootstrapping
=============================

TODO

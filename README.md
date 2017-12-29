Design Overview
===============

VSSM is a virtualized software security module. It is meant to replicate many features of a hardware security module, but with features that make it better suited to cloud deployments.

VSSM has the following properties:

* An API for standard cryptographic operations: symmetric encryption/decryption, asymmetric sign/verify, and HMAC create/verify.
* Non-exportable secrets. That is, there is no API for exporting key material used in the above operations.
* Auto-scalable architecture. VSSM uses a cloud-provider mechanism for attestation so that existing instances of VSSM can supply key material to new instances.

When an instance of VSSM first comes online, it needs to bootstrap itself. This can be one in one of two ways.

1. If it is the first instance, a user needs to manually supply the RPC certificate private key.
2. If it is not the first instance, the service will discover other instances and use the cloud-provider attestation mechanism to get the RPC certificate private key from another instance.

Either way, once an instance comes online it will then use its RPC certificate to synchronize the VSSM keystore from any other instances.

Trust Model
===========

A primary goal of this application is to make keys non-exportable, similar to an HSM appliance. However, we still need to provide some kind of export mechanism for two purposes. First, nodes need to be able to synchronize state; the provides a mechanusm where injected keys can be shared across all instances. Further, it provides a way for an instance to bootstrap itself from other instances. Secondly, we want to provide a means to create backups of the key inventory in an encrypted form so that keys can be restored in case that all VSSM instances are lost.

To achieve this, key inventory can be exported using some APIs, but when this is done the inventory is protected using the RPC certificate private key. This key is a shared secret amongst VSSM instances, so all instances can use it to synchronize state, bootstrap key inventory, and restore from backups.

This key can come from one of two places, which means these must be parties that you implicitly trust with your key inventory. *If you do not trust these parties, VSSM is not appropriate for your infrastructure.*

1. The operator which first sets up your VSSM cluster. The first instance must be manually bootstrapped with a key, uploaded by an operator. The operator has an opportunity to make an offline backup of this key. (In fact, this is recommended so that you can recover key inventories from backup.) Since this key can be used to decrypt a key inventory export, the holder of this key has implicit access to any future key inventory.
2. The cloud provider, which has key material used for attestation. Since the auto-scalability of VSSM's design relies on instances being able to attest their identity to other instances, the ability to spoof this attestation would allow a malicious party to access the RPC certificate private key and therefore decrypt key inventory. Since your cloud provider has access to the key material necessary to perform attestation, it implicity has the means to spoof this attestation.

We note that in the context of using a software-based security solution, we are already implicitly trusting our cloud provider. Even without spoofing attestation credentials, the cloud provider also runs the hypervisor in which our VSSM instances are running. Therefore the cloud provider has direct access to memory where plaintext key material lives. Therefore, trust in the cloud provider should already be implicit. If you do not trust your cloud provider, then a hardware-backed security system is necessary and VSSM is not appropriate for your use case.

API Overview
============

During manual bootstrap, an API is made available on port 8080. This API accepts a single type of request for bootstrapping the service.

After the bootstrap phase, VSSM sets up four API ports.

1. The primary port is 8080, which has general-use endpoints (e.g. for performing encrypt/decrypt operations) as well as administrative endpoints (e.g. for injecting new keys). This port requires mutual TLS connections.

2. A second service is on 8081. This is a plaintext endpoint that is just used for simple HTTP-based healthchecks.

3. A third service is setup on port 8082. This endpoint uses mutual TLS and is only used internally by VSSM, e.g. for synchronizing key material. These endpoints are therefore not documented below. However, it is noted here so that security rules can be setup that allow instances of VSSM to make requests to other instances of VSSM on this port.

4. A fourth service is setup on port 8083. This is also an internal service port used for automatic bootstrapping of new instances. It uses server-only TLS since new instances don't have a client secret for mutual TLS. However, the only API it serves requires authentication using cloud-provider attestation.

Operator's Guide
================

Manual bootstrap:

    $ cat bootstrap.json
    {
       "rpcPrivateKey": "MIIE..."
    }

    $ curl -X POST -d @bootstrap.json http://localhost:8080/REST/v1/admin/bootstrap



Development Tips
================

Generate client CA and cert.

    openssl req -new -x509 -days 3650 -extensions v3_ca -keyout cakey.pem -out cacert.pem -nodes -subj '/CN=VSSM Client CA/'
    openssl req -new -keyout client.key -out client.csr -subj '/CN=VSSM Client/' -nodes
    openssl x509 -req -CA cacert.pem -CAkey cakey.pem -set_serial 1 -in client.csr -out client.pem -days 365 

Generate server cert and key.

    openssl req -new -x509 -days 3650 -extensions usr_cert -keyout server.key -out server.pem -nodes -subj '/CN=VSSM/'


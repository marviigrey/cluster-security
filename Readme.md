This repository focuses on kubernetes cluster security practices.

Objectives: 

- Understanding kubernetes attack surface.
- cluster setup and hardening.
- System Hardening.
- minimizing Microservices vulnerabilities.
- Supply chain security.
- monitoring, logging and runtime Security.

Understanding k8s attack surface:
This breaks down the methods hackers use to enter applications hosted on containers,cloud or a cluster, It also explains best practice which you can use to implement the 4Cs of cloud native security which are cloud,cluster,container and code. Attackers can come in from any of the 4 areas. Firstly, they scan for vulnerabilities in these places and if found any, force their way into your application and mess things up for you. Lets break the Cs down:

1. Cloud: The cloud can be where your cluster, datacenters, Networking system, or servers might be hosted. So we need to ensure security in this place.
2. Cluster: Ensure that all authentication Authorization admission are properly configured to avoid attacks at cluster level.
3. Containers: Implement restrictions on images, supply chains, sandboxing and also restriction on priviledged containers.
4. Code: Lastly, the codes for your application should contain important stuff like database login credentials and developers must follow code security best practices.

Cluster Setup And Hardening:
Before setting up a cluster or container on our virtual machine, it is always adviced to run security checks or assessment on the host machine. We make use of the CIS benchmark tool which is a non profit organisation that helps businesses and government protect themselves against pervasive cyber threats or attack.
CIS Benchmarks:
Center for internet security.
kube bench: an aqua security opensource tool for running CIS benchmark assessment for your kubernetes cluster.

 --------------------------------------------------------------------------------------------------------------------
 When working with TLS certificates in kubernetes, a lot of certficates are created in the cluster to enable a secure communication between every components in our cluster. The main components such as the controller-manager, the kubelet-server, the kube-proxy, kube-scheduler, etc, all have encrypted TLS certificates generated with the openssl tool. 
 When creating all certificates for the components of the cluster, ensure to create a certificate authority certificate for signing all other certificates that has been generated for the compnents of our cluster. A CA will serve as the root cert for the cluster since all components make use of it, and every component must have the public key of the root cert to enable communication between them and the kube-api server.
 This certificate help the components of the cluster to make API calls to the kube-api server. so when we want to make an api call to the server we can run:

        curl https://kube-apiserver:6443 --cacert --api-cert get pods.
    
Filling in such details won't be so much fun that's why they are specified within the kube-config.yaml file as parameters.


Creating a self-signed certificates for our kubernetes cluster:
NOTE: this is for learning purpose and not for production purpose, However, it is advised to use a Well known CA such as digicert and the rest for real life purpose.

1. Create a certificate Authority - CA public and private key.
        
        openssl genrsa -out ca.key 2048

2. create a certificate signing request for the CA.

    openssl req -new -key ca.key -subj "/CN=KUBERNETES-CA" -out ca.csr

3. sign the csr file by yourself(self-signed).

    openssl x509 -signkey ca.key -req -in ca.csr -out ca.crt

After creating our self-signed root certificate, we move on to creating the client certificates and sign them using the root certificate.
Steps: 
1. create a key pair using openssl.

    openssl genrsa -out admin.key 2048

2. generate a csr:

    openssl req -new -key admin.key -subj "/CN=kube-admin/O=system:masters" -out admin.csr

3. sign the cert using our previously created CA cert:

    openssl x509 -req -CAkey ca.key -in admin.csr -CA ca.crt
    #note: the ca certificate you use to sign your client certs is only valid within your cluster.

This is how client certificates are generated and validated, we follow the same processes for other clients certs like controller manager,scheduler etc. For the server and clients certificates to verify the root certs, they all need a copy of the root public cert for it to establish communication between the both parties.
For the server side such as the ETCD,kubelet and kube-api server, starting with the etcd server:
firstly, we generate key pairs for the server, sometimes, we might have a situation where the ETCD server is an external server outside of the cluster which will result in creating peer of keys to enable communication between every etcd member of the cluster. So when all procedures are followed after generating key pairs,csr and validating them, we can specify this information in the etcd.yaml manifest file, this file contains info such as the CA cert, peer trusted CA filem the public and private keys, the endpoints of the servers etc. Most important cert will be the Root cert. This cert ensures that communication between the etcd servers and the kube-api server within the cluster is valid.
Fort
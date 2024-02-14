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
One thing to note is that the kube-api server is the root of kubernetes and it is addressed with so many names. ALl the names can be configured inside an openssl.cnf file, the purpose of this action is to establish a secured connection between the kubeapi and other components that addresses the kube-apiserver by the name listed in the openssl config file. So after generating key pairs and csr, pass the openssl config file as an option using the -config option:

    openssl req -new -key apiserver.key -subj "/CN=kube-apiserver" -out apiserver.csr -config <openssl-config-filename>

All this are going to be parsed in the kubeapi executable config file.

//viewing details of kubernetes tls cert files. 
1. understand the type of installation: either hardway or kubeadm. 
kubeadm- cat /etc/kubernetes/manifests/kube-apiserver.yaml.
2. decode the cert if found using openssl command.
    openssl x509 -in <cert file path> -text -noout

This will release information about the certificate.

The CA cert files are really important because anybody with access to them literally have access to your cluster, the ca file can be used to grant access to users into your cluster. With the CA cert, youre able to use it to grant a signing request presented by the user. After this, the user then recieves the signed cert and now has access to communicate to our kube api server because of a signed certificate by the Certificate Authority.

The CA signing request controller helps in authenticating users into our server. It performs all the signing task by using a kubernetes resource to approve users CSR and gives authentication to the requested user. After a user generate the key pairs and decides to create a signing request for the key, he encodes the key and parse it into a csr yaml manifest file and run the "kubectl create -f <file.yaml>". This will automatically create a csr resource in our cluster and this can only be approved by the kube admin.

==============================================================================

RBAC: 
Role-based access control (RBAC) is a method of regulating access to computer or network resources based on the roles of individual users within your organization.

RBAC authorization uses the rbac.authorization.k8s.io API group to drive authorization decisions, allowing you to dynamically configure policies through the Kubernetes API.

In kubernetes, we make use of clusterroles, roles, rolebindings and clusterrolebindings.
What's the difference?
The clusterroles and clusterolebindings are cluster-scoped. which means you can grant a user access to the anything in the cluster and not within a namespace. For the Roles and rolebinding, they are namespace-scoped. which means a user is only allowed to take actions within a  namespace. If you want users to have acess cluster-wide, use the clusterrole and clusterrolebinding.
-----------------------------------------------------------------------------------------------
Kubelet Security:
As we all know that the kubelet is like slave to the master node or controlplane. It receives instruction from the controlplane and carry out the instructions on the worker nodes. What if we get in a situation where the kubelet starts to recieve instructions from a different controlplane? this significantly means that the security of our kubelet has been breached.

View kubelet options:
This command will help us understand how the kubelet is configured on our machine and different options. 
we can find the kubelet in the /var/lib/kubelet/config.yaml.
        ps -aux | grep kubelet.service

Ensuring security in kubelet:
1. Disable anonymous authententication in our kubelet config file which can be found in the path: /var/lib/kubelet/config.yaml file.
   By default, anyone with the ip of cluster host is able to ping our cluster's api. So disabling it will no longer give anyone access to our kubelet api again. All APIs including the api carrying system logs are exposed by default, this will be a great security measure when creating a cluster.


Authentication-Based-Mechanism:
- Certificates (X509): Create pairs of certs to serve the kubelet service, provide a CA file path to the client-ca option in kubelet config file. The kub-api-server must also have the kubelet certs for the purpose of authentication when communication.(Recommended Approach)
- API Bearer Tokens.

2. Set ReadOnlyPort to 0. this will block all request to the /metrics endpoint of our kubelet.
3. Set authorization mode to Webhook: when set to webhook, the kubelet makes a call to the API server to determine whether each requests can be authorized or not. It can either reject or accept the request depending on the result received from API server.

Kubectl Proxy & Port forwarding

kubectl proxy --port=<port-number>
kubectl port-forward pod/pod-name vm-port:pod-port (same for deployments or service.)
Accessing the kubernetes dashboard:
1. Create  a proxy.
2. go to your web browser and access:
    - https://localhost:8001/api/vi/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy

We can control access to our kubernetes dashboard using service accounts, clusterrole and clusterrolebindings. 

We can confirm release binary of kubernetes engine using the sha512sum command. When we download a version of kubernetes and maybe a part of the configuration has been modified, you can download the release version of the k8s engine and run

        sha512sum -a <kubernetes-release-binary>

After doing this, you can check the official doc page to confirm if your source code matches with the one on your system.
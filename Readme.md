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

---------------------------------------------------------------------------------------------------------------------------
Reference-links:
https://github.com/kubernetes/kubernetes/releases

https://github.com/kubernetes/design-proposals-archive/blob/main/release/versioning.md

https://github.com/kubernetes/design-proposals-archive/blob/main/api-machinery/api-group.md

https://blog.risingstack.com/the-history-of-kubernetes/

https://kubernetes.io/docs/setup/version-skew-policy

Cluster Upgrade Process:
In a k8s release version, all components have similar version numbers. Which means components such as the kube-apiserver, controller-manager,kube-scheduler,kubelet all have the ame version number. While the ETCD and coreDNS have different version numbers because they are managed differently. The kube-api server has the highest version update because it is the main component every other component talks to. other components could be two versions or one version lower but not higher than the kube-apiserver version. The kubectl doesn't follow this rule. The kubectl can be a version higher or lower than the kube-api-server or even two version lower than the kube-apiserver.

upgrading your cluster using the kubeadm tool:
NOTE: the kubeadm does not upgrade kubelets on worker nodes, this should be done seperately on each worker node.
1. Get information about kubeadm, latest version and updates available:

        kubeadm upgrade plan

2. Download latest update of kubeadm

        apt-get upgrade -y kubeadm=<version>

3. Apply update on kubeadm: 
        kubeadm upgrade apply <version>

4. upgrade the kubelet on master node:

        apt-get upgrade -y kubelet=<version>

5. Restart kubelet:
        systemctl restart kubelet.service
-----------------------------------------------------------------------------------------------------------------
Upgrading the worker Node:
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm

1. drain worker node.

        kubectl drain <worker-node-name>

2. upgrade kubeadm tool on nodes:

        apt-get upgrade -y kubeadm=<1.2x.x-00>

3. upgrade kubelet:

        apt-get upgrade -y kubelet=<version>

4. upgrade kubelet node configuration:

        kubeadm upgrade node config --kubelet-version v1.12.0

5. Restart kubelet service:

        systemctl restart kubelet.service

6. Mark nodes schedulable:

        kubectl uncordon node-1

==============================================================================================
Network policies in kubernetes is a resource type that helps a kube-admin restrict access to 
applications hosted on pods within your cluster. This implementation can help in different scenerios such as restricting the web application pod from accessing the database pods in your cluster. 

Here's an example of a network policy resource file:

                apiVersion: networking.k8s.io/v1
                kind: NetworkPolicy
                metadata:
                name: test-network-policy
                namespace: default
                spec:
                 podSelector:
                  matchLabels:
                        role: db
                policyTypes:
                - Ingress
                - Egress
                   ingress:
                        - from:
                          - ipBlock:
                                cidr: 172.17.0.0/16
       
                - namespaceSelector:
                   matchLabels:
                     project: myproject
                - podSelector:
                   matchLabels:
                    role: frontend
                ports:
                - protocol: TCP
                  port: 6379
                 egress:
                 - to:
                   - ipBlock:
                     cidr: 10.0.0.0/24
                   ports:
                   - protocol: TCP
                     port: 5978

podSelector: Each NetworkPolicy includes a podSelector which selects the grouping of pods to which the policy applies. The example policy selects pods with the label "role=db". An empty podSelector selects all pods in the namespace.

policyTypes: Each NetworkPolicy includes a policyTypes list which may include either Ingress, Egress, or both. The policyTypes field indicates whether or not the given policy applies to ingress traffic to selected pod, egress traffic from selected pods, or both. If no policyTypes are specified on a NetworkPolicy then by default Ingress will always be set and Egress will be set if the NetworkPolicy has any egress rules.

ingress: Each NetworkPolicy may include a list of allowed ingress rules. Each rule allows traffic which matches both the from and ports sections. The example policy contains a single rule, which matches traffic on a single port, from one of three sources, the first specified via an ipBlock, the second via a namespaceSelector and the third via a podSelector.

egress: Each NetworkPolicy may include a list of allowed egress rules. Each rule allows traffic which matches both the to and ports sections.

---------------------------------------------------------------

Ingress:
Ingress helps users access your application using a single Externally accessible URL that you can configure to route to different services within your cluster, At the same time implementing SSL security.

For your ingress to work in your kubernetes cluster you will need an ingress controller. An ingress controller is responsible for managing inbound traffic to the Kubernetes cluster. It acts as a gateway, handling external requests and routing them to appropriate services within the cluster based on defined rules and configurations. There are different examples of controllers such as NGINX, TRAEFIK etc. USing NGINX controller, we have certain resources For configuring the an ingress controller on your cluster:

- Deployment.
- Service.
- ConfigMap 
- Auth

Ingress resource:
 An ingress resource is a set of configuration and rules applied on an ingress controller, you can configure rules to forward traffic to a single application or set of applications.

        
 apiVersion: networking.k8s.io/v1
 kind: Ingress
 metadata:
  name: minimal-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
 spec:
  ingressClassName: nginx-example
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80


        

Creating an nginx ingress-controller:
1. Create a namespace called ingress-nginx

     kubectl create ns ingress-nginx

2. The NGINX Ingress Controller requires a ConfigMap object. Create a ConfigMap object with name ingress-nginx-controller in the ingress-nginx namespace.

3. The NGINX Ingress Controller requires two ServiceAccounts. Create both ServiceAccount with name ingress-nginx and ingress-nginx-admission in the ingress-nginx namespace.

        kubectl create sa -n ingress-nginx ingress-nginx ingress-nginx-admission

4. create RBAC authorization.
                apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: "2024-02-18T14:36:06Z"
  labels:
    app.kubernetes.io/instance: ingress-nginx
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
    app.kubernetes.io/version: 1.1.2
    helm.sh/chart: ingress-nginx-4.0.18
  name: ingress-nginx
  resourceVersion: "1274"
  uid: ccb55434-3b82-476f-8863-47e0cef00734
 rules:
 - apiGroups:
   - ""
   resources:
    - configmaps
    - endpoints
    - nodes
    - pods
    - secrets
    - namespaces
   verbs:
   - list
   - watch
    - apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - services
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
  - patch
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses/status
  verbs:
  - update
- apiGroups:
  - networking.k8s.io
  resources:
  - ingressclasses
  verbs:
  - get
  - list
  - watch





        
        


--------------------------------------------------------------------------------------------------------------------

NOTE: Docker server configuration:
The docker cli runs the docker daemon as a service in the background, this helps us to manage the docker configuration and set security measures using the daemon.json file located at /etc/docker/ directory. It contains path to tls certificates used for authenticating users that can communicate with the docker cli engine.

SYSTEM HARDENING:

A way to limit threats and reduce attack surface is to keep all systems in the cluster in a simple and consistent state.
if a node that's part of a cluster gets poorly configured can lead the whole system to a possibilty of attacks.

Limited Access To Nodes:

A well recognised method of limiting access to the controlplane node isby deploying the node in a private network. for managed kubernetes service it is possible that you will have no access to the control plane components, but this is not the same for self-hosted kubernetes engines. Another option is to enable authorized networks within the infrastructure firewall. This is applied based on the source ip address range that we can define on the infrastructure firewall.
Access to Nodes? 
account types: 
 - user accounts: bob,michael, grey etc.
 - superuser accounts: UID=0, root user access.
 - systemAccounts: created during OS creation and mainly used by softwares and services,they do not run as superuser.
 - serviceAccounts: similar to system accounts and are created when services are installed e.g nginx apache http etc.

/etc/passwd contains information about users account in the system.
/etc/shadow - contains the users account passwords. the content of this file is hashed.
/etc/group - contains information about groups that users belong to.

With the knowledge of what contents are stored in the above files, we can control access to our host system by taking actions like deleting unwanted users with the usermod command.

                usermod -s /bin/nologin <username>
                userdel <username>

We can also remove user from groups they shouldnt belong to:

                deluser <username> <groupname>

We can also improve the security of our nodes by securing the SSH service:
Accessing a server can be done using username and password or by using cryptographic key pairs (public and private). The SSH service is an inbuilt system service that authenticates user access into the system.
generating keypairs for remote access:

//creates two keys public and private. public can be shared but not the private.

        ssh-keygen -t rsa

        ssh-copy-id -i <username@ipaddress>

Hardening ssh for root account:

To disable root ssh, update the ssh configuration file located at /etc/ssh/ssh/sshd_config and update the root login permission to no:

                PermitRootLogin no

We can also disable password authenticationa and allow ssh login via sshkeys only:

                PasswordAuthentication no

To escalate user priviledges we can make use of `sudo` . The sudo config file can be found in the /etc/sudoers file.
To add users to be able to use sudo, eit the /etc/sudoers file and add:
                <username> ALL=(ALL:ALL) ALL
                <username> ALL=(ALL:ALL) NOPASSWD:ALL

Ensure that the public key of the client server is copied to the remote server.

RBAC access.
Remove obsolete packages and services.
Restrict Network access.
Restrict obsolete kernel modules.
identify and fix open ports.

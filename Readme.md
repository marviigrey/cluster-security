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


Remove obsolete packages and services:
 We can also keep our system safe by making sure only required softwares are installed on them, and the ones that are installed are constantly updated to address security fixes. This is because new vulnerabilities are discovered everyday and why we need to constantly update our packages and softwares ina  timely manner.
 Services are used to start application during a linux system boot. they are managed by the systemd, usin the systemctl,we are able to see the status of our service, start or stop the service. The service configuration files are stored in the /lib/systemd/system directory. If a service is not needed, its advisable to stop or disable the service.

                systemctl list-units --type service

                systemctl disable <servicename>

                systemctl stop <servicename>

                apt remove <packagename>



Restrict Network access.
Restrict obsolete kernel modules: 
The linux kernel module has a modular design that extends it capabilities by the means of dynamically loaded kernel modules. This means that when a hardware device is connected to our system, they can be made available to the users by loading the corresponding kernel modules. It's important to blacklist all modules that are of no use to the kubernetes cluster. this step should be performed on all nodes on the cluster to mitigate vulnerablilties or attack to our network related modules. Blacklisting is a context of kernel modules as a mechanism to prevent the kernel module from loading. 

        modprobe <module name>
        lsmod //list all available module

To balcklist a module that's of no use,add the module name to `/etc/modprobe.d/blacklist.conf`. e.g

        cat /etc/modprobe.d/blacklist.conf
        blacklist sctp
        blacklist dccp

The module `sctp`  and `dccp`are of no use to k8s cluster so it's therefore blacklisted. reboot the system and run `lsmod` to confirm if the modules are available or not.

identify and fix open ports:
when several processes are started on a system, they are mostly bound to a port. A port is an addressable location in the OS that allows the segregation of network traffic intended for different applications. to check if ports are used and listening for requests run:

        netstat -an | grep -w LISTEN

/etc/services file stores information about services in our system, to get what service is running on a particular pport we can run

        cat /etc/services/ | grep -w <portnumber>


Minimize IAM policies and Role:

In the previous writeup, we explained how we can protect our self-hosted k8s machine using some preventive measures in linux. In a case where we have the k8s engine on a cloud platform like aws, we make use of identity access management to control access to our cloud platform user interface. It's never adviced to control or use any k8s resources. It's better to use an IAM user to control all operations. An attack on the root account will compromise every resource within the cloud platform. The root user account should only be used to create IAM user which will be used to operate our clusters.
Also we can make use of permissions and policies to control access and priviledges on our cloud platform. We make use of IAM role to have our resources within the cloud to integrate with themselves. 

Restrict Network Access:
In a real world scenario where we have so many network configuration, involving multiple network switches and routers, it is important to implement a network security policy to help restrict access to services and ports. We can apply security firewalls such as cisco ASA,juniper NGFW, Barracuda NGFW, fortinet etc. Using these firewalls, you can define rules that will control any traffic flowing in and out of the network. Alternatively, we can attach these policies at individual servers level using IPtables,FireWallD,NuFW and firewalls in windows servers.

UFW: Uncomplicated Firewall.
If we have apps or softwares running on a linux system and we want specific network settings like allowing only 2 ports opened, one for clients and the other for endusers accessing application running on our linux system. To achieve this , we make use of netfilter, an internal packet filtering system available in the linux kernel.
Installing the UFWon ubuntu:
- update apt package manager.

                sudo apt-get update

- Install ufw

                sudo apt-get install ufw

- enable ufw

                systemctl enable ufw

- start the ufw service.

                systemctl start ufw

- Check status of the ufw

                ufw status

Configuring the ufw to allow all outgoing and deny all incoming requests:

        ufw default allow outgoing

        ufw default deny incoming

To allow inbound connection from a specific ip address through the port specified, using UFW run:

        ufw allow from <ipaddr> to any port 22 proto tcp

You can also pass this rule to cidr blocks and not just a specific ip.:

        ufw allow from 172.16.100.0/28 to any port 22 proto tcp

YOu can deny any connection coming from a specific port:

        ufw deny 8080


To activate the firewall after setting these rules run:

        ufw enable

        ufw status

To delete a specific rule:

        ufw delete deny 8080


Linux Syscalls:

a kernel is one of the most important component of an operating system. It is the core interface between a computer's hardware and it's processes, It communicates between the two, managing resources as efficiently as possible.
kernel memory area:
- kernel space: Kernel code, Kernel Extensions, Device drivers .
- user space: programming languages such as python C java Ruby etc.

Applications running in the user space get access to data on the device by making special requests to the kernel. this process is called system calls.

Tracing System Calls:
Strace: the "strace" utility is installed in most linux distro and it is useful to trace the system calls used by an application, and the signals written back to it.Example: 

                strace touch /tmp/error.log

The result of this command provides information such as the syscall name, the arguement passed to the syscall and the written status.

To trace a ssycall process,we first need to identify the PID of the process, example:

                pidof <process>

        #take the id of the process and run:

        strace -p <PiD>

Run this command to view all syscall of any process:

                strace -c touch /tmp/error.log
This will display a list of syscalls the "touch /tmp/error.log" command can make.

AquaSec Tracee:
Tracee is an open-source tool created by Aqua Security that makes use of EBPF to trace the system at runtime.
EBPF stans for "Extended Berkerley Packet Filter" that runs programs directly on linux kernels space without interfering with the kernel source code or loading any kernel module.
We can run the Aqua tracee as a docker container instead of going through the stress of installing it using system dependencies.
Tracee needs priviledged capabilities to perform tracing when running as a docker container so passing the --priviledged additional capability when running on docker container helps add the ability.

Restricting Syscalls with seccomp:
A system with too many syscalls opened stands the risk of getting attacked, one possible way to mitigate the risk is by restricting syscalls that are not needed by an application.
By default, the linux kernel will allow any syscall to be invokedvby programs running in the userspace which can increase the attack surface.
SECCOMP: Secure Computing which is a linux kernel level feature that can be used to sandbox applications to only use the syscalls they need.
To check if your OS supports seccomp, check your boot config file by running:

                grep -i seccomp /boot/config-$(uname -r)

        response:
                node:~/cluster-security$ grep -i seccomp /boot/config-$(uname -r)
                CONFIG_HAVE_ARCH_SECCOMP=y
                CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
                CONFIG_SECCOMP=y
                CONFIG_SECCOMP_FILTER=y
                # CONFIG_SECCOMP_CACHE_DEBUG is not set

Tesiing the seccomp:
1. run a simple docker container and exec into it:
        docker run -it --rm docker/whalesay /bin/sh
2. Get the PID 

        ps -ef

3. test the seccomp mode by changing the date.

        date -s '19 APR 2012 00:00:00' 

You will get an error like this:
"date: cannot set date: Operation not permitted
Thu Apr 19 00:00:00 UTC 2012".

Reason being that the container which we used in making the test is a docker container, docker containers have an in-built seccomp filter which is used by default provided that the host kernel has seccomp enabled.

Seccomps mode: 
Mode 0 - DISABLED - This implies that seccomp is disabled.
MOde 1 - STRICT - Seccomp will block all syscalls except from 4: read, write, exit and cigratte
Mode 2 - FILTERED: seccomps is operating i the system.

A seccomp whitelist filter document contains 3 objects:
1. systems architecture, e.g 32bit.
2. syscalls arrays: defines syscalls name and associated sction either to allow or deny a syscall.
3. Default array: specifies actions to be taken on syscalls that have not been declared in the syscall array. This will reject all other syscalls by default.

Another syscall profile type called the blaclist.json doc. It does the exact opposite of everything the whitelist does, it allows all syscalls by default and denies the syscalls defined in the syscall array.
Blacklist profile are way more open than the whitelist, also they are more susceptible to attacks as they allow all syscalls by default, if a potentially dangerous syscall is not added to the blacklist, this can lead to security incident.
The default docker seccomp setting blocks about 60 of the 300 plus syscalls  on the x86 achitecture.
Another thing to note that you can have or create a custom syscall that you can use for your containers aside the default seccomp file. instead when running the container, we can parse it as a flag like this:

                docker run -it --rm --security-opt seccomp=/root/custom.json \ docker/whalesay /bin/sh

To make use of syscalls within a container we can set the seccomp flag to "uconfined". This will allow all syscalls within the container.

                docker run -it --rm --security-opt seccomp=unconfined \ docker/whalesay /bin/sh
Note: the above method should never be used and we should resort to using custom profile to restrict or allow specific syscalls when necessary. There are additional security gates built into docker which prevent you from running several syscalls even with seccomp disabled. Even if you try it with a second profile it won't work.

Implementing seccomps in kubernetes:
Firstly testing if seccomp is configured in your container orchestrator using an opensource tool called amicontained. It is a tool designed to help understand and validate the container environment in which it runs. It's particularly useful for security auditing, compliance, and ensuring that containers adhere to best practices. It provides an important information such as syscalls that are blocked, seccomp mode etc. 
To run it on your docker environment, run:

        docker run --rm -it r.j3ss.co/amicontained

On kubernetes, run as a pod: 

        kubectl run amicontained --image r.j3ss.co/amicontained amicontained -- amicontained

        kubectl logs amicontained

For resources in a kubernetes environment, seccomp is disabled by default but you can add them to a resource definition file under the security context field:

        apiVersion: v1
        kind: Pod
        metadata:
                name: default-pod
                labels:
                app: default-pod
        spec:
                securityContext:
                        seccompProfile:
                                type: RuntimeDefault
                 containers:
                - name: test-container
                image: hashicorp/http-echo:1.0
                args:
                -   "-text=just made some more syscalls!"
                securityContext:
                  allowPrivilegeEscalation: false

To use a custom profile from your local machine, change the type to localhost and add localHostProfile tag and the path to the file like this:
        securityContext:
                        seccompProfile:
                                type: Localhost
                                localhostProfile: <path to the custom json file>
The preconfigured path for kubernetes is /var/lib/kubelet/seccomp.

Create a directory in the /var/lib/kubelet/seccomp called profiles:
        mkdir -p /var/lib/kubelet/seccomp/profiles
        #create an audit profile which will log all syscalls generated by the process running in the container. add the default action set to SCMP_ACT_LOG:

                {
                        "defaultAction: "SCMP_ACT_LOG"
                }

Once the pod is created, the syscalls generated by the system will be logged in the container in /var/log/syslog path. the logs will contain info such as user id, group id and the syscall itself. To identify the syscall associated with id, we check the /usr/incude/asm/unitstd_64.h file and map it to the number.
We can also make use of the tracee to check for syscallson all new containers in the host.

Restrict Syscalls :
1. create another profile and call it violation.json
2. this time, the profile should block OR REJECT all syscalls.
3. add the profile using the custom newly created profile in the pod definition file
=====================================================================================================================

App Armor: 
AppArmor is a linux security module which is used to confine a program to a limited set of resources, it is intalled by default in most linux distros. To check if apparmor is installed on your linux system by default, run: 

                systemctl status apparmor

To make use of apparmor on containers running on nodes, ensure that the appArmor kernel module has been loaded by the node. Check the /sys/module/apparmor/parameters/enabled to see if it is enabled:

                cat /sys/module/apparmor/parameters/enabled

                Response: Y

Just like the seccomp profile, appArmor makes use of profiles to restrict application progams to limited capabilities. The profile file can be located at /sys/kernel/security/apparmor/profiles. to view, run:

                cat /sys/kernel/security/apparmor/profiles

        response:
        docker-default (enforce)
        snap.snapd-desktop-integration.snapd-desktop-integration (enforce)
        snap.tree.tree (enforce)
        snap.snap-store.ubuntu-software-local-file (enforce)    
        snap.snapd-desktop-integration.hook.configure (enforce)
        snap.snap-store.ubuntu-software (enforce)
        snap.snap-store.snap-store (enforce)
        snap.snap-store.hook.configure (enforce)
        snap.jq.jq (enforce)
        snap.kubectl.kubectl (complain)
        snap.helm.helm (complain)
        snap.go.gofmt (complain)
        snap.go.go (complain)
        snap.firefox.hook.disconnect-plug-host-hunspell (enforce)
        snap.firefox.geckodriver (enforce)
        snap.firefox.hook.post-refresh (enforce)
        snap.firefox.firefox (enforce)
        snap.firefox.hook.connect-plug-host-hunspell (enforce)
        snap.firefox.hook.configure (enforce)
        snap.docker.nvidia-container-toolkit (enforce)
        snap.docker.hook.post-refresh (enforce)
        snap.docker.hook.install (enforce)
        snap.docker.hook.connect-plug-graphics-core22 (enforce)
        snap.docker.hook.configure (enforce)
        snap.docker.help (enforce)
        snap.docker.docker (enforce)
        snap.docker.compose (enforce)
        snap.docker.dockerd (enforce)
        snap.core.hook.configure (enforce)
        snap-update-ns.snapd-desktop-integration (enforce)
        snap.code.code (complain)
        snap.code.url-handler (complain)
        snap.aws-cli.aws (complain)
        snap-update-ns.snap-store (enforce)
        snap-update-ns.tree (enforce)
        snap-update-ns.kubectl (enforce)
        snap-update-ns.jq (enforce)
        snap-update-ns.helm (enforce)
        snap-update-ns.firefox (enforce)
        snap-update-ns.go (enforce)
        snap-update-ns.core (enforce)
        snap-update-ns.docker (enforce)
        /snap/snapd/20290/usr/lib/snapd/snap-confine (enforce)
        /snap/snapd/20290/usr/lib/snapd/snap-confine//mount-namespace-capture-helper (enforce)
        /snap/snapd/20671/usr/lib/snapd/snap-confine (enforce)
        /snap/snapd/20671/usr/lib/snapd/snap-confine//mount-namespace-capture-helper (enforce)
        snap-update-ns.code (enforce)
        /snap/core/16574/usr/lib/snapd/snap-confine (enforce)
        /snap/core/16574/usr/lib/snapd/snap-confine//mount-namespace-capture-helper (enforce)
        snap-update-ns.aws-cli (enforce)
        libreoffice-soffice (complain)
        libreoffice-soffice//gpg (enforce)
        /usr/sbin/mysqld (enforce)
        /usr/sbin/cupsd (enforce)
        /usr/sbin/cupsd//third_party (enforce)
        /usr/lib/cups/backend/cups-pdf (enforce)
        /usr/bin/evince-thumbnailer (enforce)
        /usr/bin/evince-previewer (enforce)
        /usr/bin/evince-previewer//sanitized_helper (enforce)
        /usr/bin/evince (enforce)
        /usr/bin/evince//snap_browsers (enforce)
        /usr/bin/evince//sanitized_helper (enforce)
        /usr/sbin/cups-browsed (enforce)
        /usr/lib/snapd/snap-confine (enforce)
        /usr/lib/snapd/snap-confine//mount-namespace-capture-helper (enforce)
        libreoffice-xpdfimport (enforce)
        tcpdump (enforce)
        libreoffice-oosplash (complain)
        libreoffice-senddoc (enforce)
        man_groff (enforce)
        man_filter (enforce)
        /usr/bin/man (enforce)
        /{,usr/}sbin/dhclient (enforce)
        /usr/lib/connman/scripts/dhclient-script (enforce)
        /usr/lib/NetworkManager/nm-dhcp-helper (enforce)
        /usr/lib/NetworkManager/nm-dhcp-client.action (enforce)
        nvidia_modprobe (enforce)
        nvidia_modprobe//kmod (enforce)
        lsb_release (enforce)

AppArmor profile are simple text files that describes what resources can be used by an application, such as linux capabilities, network resources, file resources etc. examples of appArmor profile:

        profile app-armor-deny-write flags=(attach_disconnected) {
                file,
                #deny all file writes in the root directory and its sub directories.
                deny /** w,
        }

Deny writes to files in the /proc dir:


        profile app-armor-deny-proc-write flags=(attach_disconnected) {
                file,
                #deny all file writes.
                deny /proc w,
        }
Deny remounting of files in the root directory:


        profile app-armor-deny-remount-root flags=(attach_disconnected) {
                file,
                #deny remount readonly the root filesystem.
                deny mount options=(ro, remount) -> !/,
        }

The appArmor that has been loaded can be checked with the `aa-status` command.

AppArmor profiles can be loaded in 3 different modes:
1. Enforce - Apparmor will enforce the rule that is written in the profile.
2. Complain - Will allow applications to perform without restriction but it will log them as  event.
3. Unconfined - no logging of event and it is allowed to perform any task without restriction:

Creating AppArmor profiles:
To create a new appArmor profile 

------------------------------------------------------------------------------------
1. Priviledged processes: run by the root user, UID set to 0(Zero). examples of priviledge capabilities:

CAP_CHOWN: ability to change ownership of files and directories.
CAP_NET_ADMIN: make some networking changes in the system.
CAP_SYS_BOOT: Ability to Reboot to reboot the system.
CAP_SYS_TIME: Ability to change or alter the system clock

These are some examples of linux capabilities that are assigned to the priviledged user, the root user.


2. Unpriviledged processes: Non root user whose UID is not 0.

In context to kubernetes architecture, or in a situation relating to to container runtime environment, by default, all containers are created with limited capabilities set by the container runtime itself, even the root users cannot perform some actions due to some of this restrictions made by docker. 
In kubernetes we can add system capabalities into containers by specifying the capabilities in the `security` context field in our deployment or pod manifest file:

                 securityContext:
                         capabilities:
                          add: ["NET_ADMIN", "SYS_TIME"]

The container will let users make some network changes and also modification on the system clock.

Container security:
When you run a docker container, you have the priviledge to define security standards such user id, system capabilities that can be added or removed from the container, etc.
 We can also configure these settings in kubernetes,at pod or container level. NOTE: settings on the container will override settings on the pod, but they can be configured differently.

 Using security context, we can add these security configurations on pods and containers. example:
        # security context at pod level
        apiVersion:
        kind: Pod
        metadata:
          name: test-pod
        spec:
                securityContext:
                        runAsUser: 1000

        # security context at container level:

        # NOTE: capabilities are only supported at conttainer level and not pod level.
        containers:
          - name: ubuntu
            image: ubuntu
            command: ["sleep", "3000"]
            securityContext:
                capabilities:
                        add: ["SYS_NET_ADMIN"]


Admission Controllers:
kubectl --->kube-API---->authentication----authorization--AdmissionControllers-->create pod

In situation where we want certain security configuration based on different fields such as authentication and authorization, we can't implement every security steps using just pods or RBAC(roles and rolebindings, clusterroles and clusterrolebindings). Admission controllers helps us implement security measures to enforce how a cluster should be used.
Apart from simply validating configurations, admission controllers can change requests or perform additional operations before the main operation, like create a namespace before creating a pod.

Examples of admission controllers:
1. `AlwaysPullImages` : Everytime pod is created, images are always pulled
2. `DefaultStorageClass` : each time PVs and PVCs are created, a default storage class is added them
3. `EventRateLimit` : limits the rate at which the kube api server handles requests.

There are many admission controllers, to see a list of admission controllers, run:
        kube-apiserver -h | grep enable-admission-plugins

        # in a kubeadm setup run:

        kubectl exec kube-apiser-controlplane -n kube-system --kube-apiserver -h | grep enable-admission-plugins

To add an admission controller to your cluster, update the `- --enable-admission-plugins` in the kube-apiserver manifest file :

                - --enable-admission-plugins=<admission-controller-name>

Validating and mutating admission controllers:

Validating: Just as the `NamespaceLifecycle` admission controller, it validates a namespace if it exists and reject the request if it doesnt exist. This is what the validating admission controller does.

Mutating : for the mmutating, it can changee or mutate the object itself before it's created.

Validating controllers are invoked first before the mutating controllers. 

MutatingAdmissionWebhook, ValidatingAdmissionWebhook:
We can configure this webhooks on a server that's either within the cluster or outside it. Our server  will have our own admission webhook service running with our own code and logic
Kubernetes supports external admission controllers that we can use for mutation and validation namely MutatingAdmissionWebhook and ValidatingAdmissionWebhook. 

Steps to deploy admission controller:
- Develop a webhook server using and programming language of your choice.
- host your webhook server on vm or containerize it and run it on your kubernetes cluster as a deployment.
- create a service for the deployment.
- create a validating admission webhook using a manifest.

        apiVersion: admissionregistration.k8s.io/v1
        kind: ValidatingWebhookConfiguration
        metadata:
         name: "pod-policy.example.com"
        webhooks:
        - name: "pod-policy.example.com"
        rules:
        - apiGroups:   [""]
          apiVersions: ["v1"]
          operations:  ["CREATE"]
          resources:   ["pods"]
          scope:       "Namespaced"
        clientConfig:
          service:
         namespace: "example-namespace"
         name: "example-service"
         caBundle: <CA_BUNDLE>
        admissionReviewVersions: ["v1"]
        sideEffects: None
        timeoutSeconds: 5

This is an example of an admission controller manifest file. The above file represents a validation controller which means it accepts when requests are made to create pods depending on the response, it can either allow or reject this action.

Pod Security Policies: (DEPRECATED)
Pod security policy helps us implement certain policies to restrict pods from being created with specific capabilities or priviledges.
How it works:
When podSecurityPolicy is enabled in a cluster, the admission controller validates the configuration against the set of preconfigured rules, if it detects a violation of rule, it rejects the request and retrns error to the user. The pod security policy is deployed as an admission controller and can be enabled using the kube-apiserver.yaml file:

        - --enable-admission-plugin=PodSecurityPolicy

- Create a PodSecurityPolicy resource using a manifest file.
- configure authorization using RBAC: role and  a rolebinding, service account to authorize communication between the admission controller and the kube-api-server.

Pod Security Admission And pod Security Standards:Pod security admission is also similar to the pod security policy, Its an admission controller which is enabled by default. PSA is configured at a namespace level, you do that by applying a label to the namespace.
Configuring PSA: 3 profiles are built;
- priviledged: unrestricted policy
- Baseline: minimal restrictive policy, easy to use and it helps stop users from gaining unauthorized access to higher priviledges.
- restricted: heavily restricted policy. It focuses on applying the best security measures for pods. Might cause some compatibility issue but ensures stronger security.


You can choose either of the three while configuring pod security.

A mode in Pod Security defines what action the control plane takes if the policy is violated.
- enforce: Reject Pod
- audit: record in the audit logs
- warn: Trigger user facing warning.


Since PSA are namespace scoped, to apply a security mode on them we use labels, example: enforce a restricted policy on the `payroll` namespace:

        kubectl label ns payroll pod-security.kubernetes.io/enforce=restricted

Open Policy Agent (OPA) is a policy engine that helps you enforce rules and policies across your software infrastructure. It allows you to write and manage policies in a declarative language and evaluate them against incoming requests or data. I
Install Opa:

                curl -L -o opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static

                chmod 755 ./opa


After installing OPA, next step is to load policies using a rego definition file
To load the profile we run:

  curl -X PUT --data-binary @opa.rego http:///localhost:8181/v1/policies/example1

To view the list of profiles run:

        curl http://localhost:8181/v1/policies

Opa in kubernetes(The gatekeepers approach):
With the gatekeeper approach, the admission controller works hand in hand with the OPA constraint framework.

Opa constraint frameworks is a framework that helps us to implement policies by declaring what we want to do, where we want to do and how to do it. It uses CRD-based policies that lets you set policies in a way that's easy to share and trust.

To install opa gatekeeper, we simply deploy the resources on our kubernetes cluster with a simple command:

        kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.15.0/deploy/gatekeeper.yaml

Understanding how the frameworks implements policies:

1. What we want to do: 
What requirements do i have? i want all objects in `payroll` namespace to have a `bill` label.
how do we enforce the label check? we define the policy in our `rego` code which is the language used by opa as discussed earlier. It will look like this:

        package systemrequiredLabels

        import data.lib.helpers

        violation[{"msg" msg, "details": {"missing_labels": missing}}] {
                provided := {label | input.request.object.metadata.labels[label]}
                required := {label | label := ["bill"]}
                missing := required - provided
                count(missing) > 0 
                msg := sprintf("you must provide labels: %v", [missing])
        }

2. Where do i want to enforce this requirements:
I want them to be enforced on a kubernetes admission controller. specifying the target is easy which is always going to be the `target: admission.k8s.gatekeeper.sh` . 

3. How do i specify what to check and what action to take:
Whenever an objct is created in the `payroll` namespace, ensure it has a bill label attached to it. whenever the request to create an object in the payroll namespace, comes through the admission controller, it checks to see if object has the appropriate label tagged to it.

The above code will only work for a case where we want objects to have `bill` label, but if we want to use this implementation for any other label we can make use of a constraint template. This is similar to manifest files we use in creating kubernetes resources. 

Example of constraint template:

apiVersion: [templates.gatekeeper.sh/v1beta1](http://templates.gatekeeper.sh/v1beta1)
kind: ConstraintTemplate
metadata:
 name: k8srequiredlabels
spec:
 crd:
 spec:
 names:
 kind: K8sRequiredLabels
 listKind: K8sRequiredLabelsList
 plural: k8srequiredlabels
 singular: k8srequiredlabels
 validation:
         # Schema for the `parameters` field
 openAPIV3Schema:
 properties:
 labels:
 type: array
 items: string
 targets:
 - target: [admission.k8s.gatekeeper.sh](http://admission.k8s.gatekeeper.sh)
 rego: |
 package k8srequiredlabels

 deny[{"msg": msg, "details": {"missing_labels": missing}}] {
 provided := {label | input.review.object.metadata.labels[label]}
 required := {label | label := input.parameters.labels[_]}
 missing := required - provided
 count(missing) > 0
 msg := sprintf("you must provide labels: %v", [missing])
 }

Secrets:
Secret is a kubernetes resource that is used to store sensitive information such as keys, passwords etc. They are similar to config maps except that they are stored in an encoded or hashed format.
Using a secret involves two steps:
1. create the secret.
2. Inject it into a pod.

We can create a secret either imperatively or using a declarative file. To create a secret with imperative command:

        kubectl create secret -n <namespace> <secret name> generic --from-literal=DB_Host=mysql --from-literal=DB_User=root --from-literal=DB_password=passwd

This is example of creating a secret that contains login credential of a mysql server. You can also create a secret from a file too by specifying the path to the file. To view ways you can create secrets run:

        kubectl create secret --help 

To parse in your secret into a pod, specify the name of the secret under the container section in the specification of the pod definition file.

        spec:
          containers:
          - name: web
            image: nginx
            envFrom: 
            - secretRef: 
                name: <secret-name>

Notes On Secrets: 
1. They ae not encrypted, only encoded which technically means that they are still vulnerable without encryption.
2. Do not check-in secret objects to SCM along with code.
3. Also, secrets are not encrypted in etcd, so consider encrypting secret data at rest.
4. Anyone able to create pods/deployments in the same namespace as the secrets have access to the secrets.
5. Consider third part secret store providers.
6. Configure least-priviledge access to secrets -RBAC

Improving isolation of containers using sandboxing techniques:
Containers and their hosts both share the same kernel on the machine, from the perspective of the host, its just another process that is isolated from the host. We also know that all containers running on a host machine make use of the users space, because they need to make use of the servers hardware resources, which technically means they have to make system calls. This is a problem because every container in a server makes use of the same kernel as the host, they both make syscalls to the same kernel to function properly. Attackers can probably hop into your system through a backdoor of your containers running on your system and damage things inside.

Sandboxing: 
Providing a solution to the problem mentioned earlier, implementation of sandbox.
What is sandboxing?
Sandboxing is simply a method of isolating a program from the rest of the system. An example of sandboxing is seccomp (Default seccomp profile for Docker, AppArmor.),AppArmor etc.

gVisor:
For our containerized applications, we need a stronger method of isolation between containers and the linux kernel. We plan to restrict containers from making direct system calls to the linux kernel. Thats where gVisor comes in. gVisor is a tool from google that allows an additional layer of isolation between the container and the kernel. Using the gVisor, when containers want to make calls to the kernel, it sends the request to the gVisor instead.
Two major components of the gvisor:

1. The Sentry: This is an indepedent application level kernel which is dedicated to containers. The main purpose of the sentry is to intercept and respond to system calls which are made by containers. The sentry is like the middle man sitting between the operating system and containers,guarding against any potential abuse. 

Each container sitting on a host machine has its own dedicated gVisor kernel. This means that each container will be isolated in its own sandbox which drastically reduce the attack surface.

Two disadvantages of using the gVisor:
1. Not all applications will work on it.
2. Since there are too many processes involved in making a syscall, it will make your application slower.

Container--->syscall-->gVisor--->Linux Kernel--->Hardware.

KATA CONTAINERS:
Kata Containers is another way to perform container isolation in a system. Unllike the gVisor, kata container installs each container into its own virtual machine which means each container will have its own kernel. The virtual machine created by kata containers are lightweight  and are more focused on performance. each container will consume compute resources and more memory of the system so you will need a big system to perform this method of isolation. Since kata containers need hardware virtualization support, it might not be able to run on typical service providers because not all support nested virtualization. 

NOTE:
The gVisor makes use of the runsc container runtime to create containers.

How to use container runtime to create pods in kubernetes:
For a cluster that already have kubernetes installed in them, we can create a runtime class with (runsc) as the handler.
To enable gVisor on your minikube:

        minikube start --container-runtime=containerd  \
    --docker-opt containerd=/var/run/containerd/containerd.sock

         minikube addons enable gvisor

         kubectl get pod,runtimeclass gvisor -n kube-system

This method is for minikube environment. 

Let's say we want to enable gVisor as our runtime using manifest file:

        # RuntimeClass is defined in the node.k8s.io API group
        apiVersion: node.k8s.io/v1
        kind: RuntimeClass
        metadata:
         # The name the RuntimeClass will be referenced by.
         # RuntimeClass is a non-namespaced resource.
         name: gVisor
        # The name of the corresponding CRI configuration
        handler: runsc

Use the `kubectl create -f <manifest.yaml>` to create the  runtime class.

To use a runtime to create a pod in our cluster we specify the runtime class name in the pod definition file under the spec section, like this:
        spec:

         runtimeClassName: gVisor
         containers:
         - image: nginx
           name: nginx

After creating the pod, you can test if the pod is running on the system by checking for the process using `pgrep`:

        pgrep -a nginx

Note: the default container used by k8s is `runc`.

Mutual SSL: Implementation of mTLS to secure pod to pod communication.
By default, data transmitted between two pods is uncrypted, if a pods needs data from another pod, it talks to the network connecting both pods together. This open problem, can be solved by implementing mTLS between pods. 

Pod A requests data from pod B, A sends certificate to B for B to verify,both pods request for certificates and verifies them seperately, after verifying, they make use of symmetric keys to encrypt data, this will help them have a secure communication between both pods. Pod A will have the key of B and vice versa for the purpose of an encrypted communication. 
Doing this on all pods seems difficult so implemenenting a third party program such as istio and linkerd. These programs allow service to service communication without depending on the application. this process is known as a service mesh, simply connecting multiple services together in a microsevice architecture.

We have two containers, A and B, the istio runs a side car container on both pods. When pod a wants to send data to B, the side car on A encrypts the data and forwards the data over a network. On getting to pod B, the istio sidecar on B decrypts the data and then passes it to the app running on the pod.

SUPPLY CHAIN SECURITY.

Minimize Base Image Footprint.
Rules to follow when building images:
1. Do not build an image that combines multiple applications together, such as a web server, database or other services.

2. Do not store data or state inside a container, find other ways to persist your data.

3. When selecting a base image you must choose an image with authenticity, look for image that suits your application needs. 

4. When creating images, they should be slim or minimal. This will allow images to be pulled faster from a remote repository.

5. Do not allow unecessary files in your images and remove unwanted packages in your image.

6. Run vulnerability scanning on images.

Image Security:
When we run containers on our cluster and we make use of images in the offical docker registry such as nginx, they all come from the library account which is the official account of docker that manages official images like the nginx. Same way you specify your account name when you try to pull your custom image to run your application on docker or kubernetes.
We can privatize our images by storing them in private registry like cloud AWS private registry. But how do we pull this applications? all we need is the credentials of the private registry and the server address of where they are stored:

                apiVersion: v1
                kind: Pod
                metadata:
                  name: private-reg
                spec:
                 containers:
                 - name: private-reg-container
                   image: <your-private-image>
                 imagePullSecrets:
                  - name: regcred

To configure the credentials for the private registry holding your private image, we make use of secretes:

        kubectl create secret docker-registry regcred --docker-server=<your-registry-server> --docker-username=<your-name> --docker-password=<your-pword> --docker-email=<your-email>


And thats how you set configuration for private images.

Whitelisting Allowed Registries:
It is important to have governance on images, to ensure that images are pulled from a verified registry. how do we prevent users from pulling images from unwanted registries?
We make use of admission controllers. We can create a policy to reject any image from unwanted registry and respond with an error message saying that the image is invalid. This is done by deploying a webhook server just as mentioned earlier.
Another option is deploying a OPA service and cofiguring a validating webhook to connect to the service and then creating policies to restrict untrusted registries using the `rego` tool. 
We can also use the built-in imagePolicyWebhook admission controller. 
To make use of ImagePolicyWebhook controller, you must first deploy a validating webhook server, then we can then create an admission configuration resouce:

        apiVersion: apiserver.config.k8s.io/v1
        kind: AdmissionConfiguration
        plugins:
        - name: ImagePolicyWebhook
        configuration:
           imagePolicy:
          kubeConfigFile: <path-to-kubeconfig-file>
          allowTTL: 50
                denyTTL: 50
                retryBackoff: 500
                defaultAllow: true

For the kube-config file, we have to specify the kube-config file that's carrying the certificates, keys for the webhook server and the endpoint of the wbehook server. all these will be mentioned in the requested kube config file.                

        # clusters refers to the remote service.
        clusters:
        - name: name-of-remote-imagepolicy-service
        cluster:
        certificate-authority: /path/to/ca.pem    # CA for verifying the remote service.
        server: https://images.example.com/policy # URL of remote service to query. Must use 'https'.

        # users refers to the API server's webhook configuration.
        users:
         - name: name-of-api-server
            user:
            client-certificate: /path/to/cert.pem # cert for the webhook admission controller to use
            client-key: /path/to/key.pem          # key matching the cert

After creating the admission configuration, we enable `imagePolicyWebhook` in the kube-apiserver manifest file:

        - --enable-admission-plugins=ImagePolicyWebhook

Analyzing Kubernetes resource definition files:
With static analysis,we review the resource files and enforce policies earlier in the development cycle before deploying to the cluster. We make use of a tool called `kubesec` . This tool helps analyze a given resource definition file and returns a score along with details about a critical issue that were found in it.

Install kubesec: 
        wget https://github.com/controlplaneio/kubesec/releases/download/v2.14.0/kubesec_linux_amd64.tar.gz
        tar -xvf kubesec_linux_amd64.tar.gz
        sudo mv kubesec /usr/local/bin

To test, check your deployment files:

        kubesec scan <file.yaml>

Scan Images for known vulnerabilities:
CVEs: common Vulnerabilities and Exposures.
CVEs is like a database that contain bugs of softwares and propose a solution to it. They help other engineers or developers avoid these bugs. This way, attackers don't get to hack into your system because of the preventive measures or solution provided by CVEs. The central database makes it easier for to find information concerning a certain bug, report bugs and avoid duplicate entries. 
The bugs discussed above can be anything that allows an attacker to bypass security checks and do things they aren't allowed to do. Another bug would be anything that allows an attacker to mess up your system or seriously degrade your system performance.

The CVE severity score helps us priortize what to care about and what not. The score displays the level of security of our system with the range of 1-10. If its high, there's a big problem, a low score is still a problem but not too much. This threats might be a result of  having excess packages that are not used in our containers or applications. Container scanners help look for vulnerability in the execution environment and tells you what vulnerablities they are known to have.
A solution to reduce attack surface is by removing unnecessary packages.

Trivy: an aquasecurity comprehensiv vulnerability scanner for containers and other artifacts and is suitable for integration with CICD pipelines. All you need to is present the name of the image you want to scan, it runs a vulnerabilty scan and returns a summary of all vulnerabilities detected in that image:

        trivy image <image name>
        #scan and display a severity-level.
        trivy image --severity <severity-level> <image-name>

        trivy image ignore-unfixed <image-name>

        #scan image in a tar archive file.

        trivy image --input <tar-file>

Best practices:
1. continuously rescan images.
2. Kubernetes admission controllers to scan images.
3. Have your own repository with pre-scanned images ready to go.
4. Integrate scanning into your CICD pipelines.


Monitoring, Logging and Runtime Security.
================================================================================

Perform behavioural analytics of syscalls.
In a system, if a breach occurs it is important that we react as soon as possible, we can prevent damage from spreading into other systems. How do we identify breaches in our kubernetes cluster?
Tools like Falco helps us to analyze syscalls that are used by an application inside a pod. Falco helps us to aanalyze these syscalls and filter events that are suspicious. 
Falco sits in the middle between the linux kernel space and user space with the use of a kernel module. Falco also interact with the kernel through EBPF(extended berkeley packet filter). The system calls are then analyzed by the sysdig libraries in the userspace, events are filtered by falco policy engine by making use of predefined rules that can detect whether the event was suspicious or not.  
We can install falco as a service on all nodes and also as daemonset on our kubernetes cluster,an advantage of installing falco as a service on nodes is that it can isolate itself from the cluster if its compromised.
Installing falco:
        curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

        echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
        sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

        sudo apt-get update -y

        sudo apt install -y dkms make linux-headers-$(uname -r)
        # If you use falcoctl driver loader to build the eBPF probe locally you need also clang toolchain
        sudo apt install -y clang llvm
        # You can install also the dialog package if you want it
        sudo apt install -y dialog

        sudo apt-get install -y falco

In falco,we make use of rules to create alerts when an is considered as an anomaly. 
Falco default rules: 
- A shell opened inside your container.
- sensitive files such as /etc/passwd were read inside the container.

Falco rule yaml file contains 3 elements:
rule: defines condition under which alert should be triggered and it consist of 5 mandatory keys. name(rule),description, condition,output and priority







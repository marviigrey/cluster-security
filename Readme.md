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

CIS Benchmarks:
Center for internet security.



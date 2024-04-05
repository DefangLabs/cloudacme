# Cloud Acme Lambda Function

Cloud acme lambda function is a simple project designed to be working with cloud service providers to allow the issuing, renewing and importing of SSL certificates to the users infrastructure.

Currently it only supports AWS lambda and provides HTTP01 challenge support by setting up ALB rules.

It makes the following assumption:
1. There is already a self signed SSL cert in ACM and it is attached to the ALB.
2. The labmda function is triggered by an ALB listener on port 80 with the follow rules:
    - Host header condition matching the domain name
    - Path condition for "/"
3. The lambda function has the correct permissions to operate with:
  - ACM for listing and importing certificates
  - ALB for find, adding and removal of rules
4. The trigger will be removed after a successful import of the certificate.

### Certificate renewal
The certificate renewal can be triggered by an event bridge scheduled event with a payload in the below format:
```json
{
  "domain": "example.com",
  "albArn":"arn:aws:elasticloadbalancing:123456789012:certificate/12345678-1234-1234-1234-123456789012"
}
```

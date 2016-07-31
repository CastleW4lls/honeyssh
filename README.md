### How to run it

Generate a public/private key pair, in the project root folder via: 

```
ssh-keygen -t rsa -C "server@example.com"
```

Build and run the SSH hoenypot

```
go build
```

```
./honeyssh
```
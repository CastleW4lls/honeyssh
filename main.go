package main

import (
	"github.com/sec51/honeyssh/config"
	"github.com/sec51/honeyssh/sshd"
)

func main() {

	sshdServer := sshd.NewSSHServer(config.IP_ADDRESS, config.PORT, config.HOSTNAME, config.USER, config.PASSWORD)
	sshdServer.Start()

}

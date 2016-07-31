package config

import (
	"github.com/sec51/goconf"
)

var (
	USER       = goconf.AppConf.DefaultString("user", "admin")
	PASSWORD   = goconf.AppConf.DefaultString("password", "dadada")
	IP_ADDRESS = goconf.AppConf.DefaultString("ip_address", "0.0.0.0")
	PORT       = goconf.AppConf.DefaultString("port", "22")
	HOSTNAME   = goconf.AppConf.DefaultString("hostname", "localhost.localdomain")
)

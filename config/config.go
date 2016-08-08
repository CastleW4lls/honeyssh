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

	HONEYMASTER_KEY    = goconf.AppConf.String("honeymaster.key")
	HONEYMASTER_SECRET = goconf.AppConf.String("honeymaster.secret")

	HONEYPOT_SERVICE  = goconf.AppConf.String("honeypot.service")
	HONEYPOT_IP       = goconf.AppConf.String("honeypot.ip")
	HONEYPOT_LOCATION = goconf.AppConf.String("honeypot.location")
	HONEYPOT_PROVIDER = goconf.AppConf.String("honeypot.provider")

	PROCESS_IP_URL       = goconf.AppConf.String("url.process.ip")
	PROCESS_COMMANDS_URL = goconf.AppConf.String("url.process.commands")
)

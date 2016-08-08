package models

type Command struct {
	Ip   string
	Data string
}

func MakeCommand(ip, data string) Command {
	c := Command{
		Ip:   ip,
		Data: data,
	}
	return c
}

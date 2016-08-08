package models

type BruteforceAttack struct {
	Ip        string
	User      string
	Password  string
	Succeeded bool
}

func MakeBruteforceAttack(ip, user, pass string, succeeded bool) BruteforceAttack {
	attack := BruteforceAttack{
		Ip:        ip,
		User:      user,
		Password:  pass,
		Succeeded: succeeded,
	}
	return attack
}

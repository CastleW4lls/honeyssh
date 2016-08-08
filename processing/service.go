package processing

import (
	"net/http"
	"net/url"

	"github.com/sec51/honeyssh/config"
	"github.com/sec51/honeyssh/log"
	"github.com/sec51/honeyssh/models"
	"github.com/sec51/honeyssh/utils"
)

var (
	client = http.Client{}
)

type ProcessingService struct {
	bruteforce chan models.BruteforceAttack
	commands   chan models.Command
}

func NewProcessingService(bruteforce chan models.BruteforceAttack, commands chan models.Command) ProcessingService {
	s := ProcessingService{
		bruteforce: bruteforce,
		commands:   commands,
	}

	return s
}

func (s ProcessingService) Start() {
	go processIp(s.bruteforce)
	go processCommands(s.commands)
}

func processIp(attacks chan models.BruteforceAttack) {
	for bf := range attacks {
		params := url.Values{
			"ip":                {bf.Ip},
			"service":           {config.HONEYPOT_SERVICE},
			"type":              {"bruteforce"},
			"honeypot_ip":       {config.HONEYPOT_IP},
			"honeypot_location": {config.HONEYPOT_LOCATION},
			"honeypot_provider": {config.HONEYPOT_PROVIDER},
		}

		req, err := utils.MakeRequest(config.PROCESS_IP_URL, "POST", params)
		if err != nil {
			log.Error.Println("processIp:", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Error.Println("processIp:", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Error.Printf("processIp - Got invalid HTTP response: %d\n", resp.StatusCode)
			continue
		}

	}
}

func processCommands(commands chan models.Command) {
	for cmd := range commands {
		params := url.Values{
			"ip":  {cmd.Ip},
			"cmd": {cmd.Data},
		}

		req, err := utils.MakeRequest(config.PROCESS_COMMANDS_URL, "POST", params)
		if err != nil {
			log.Error.Println("processCommands:", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Error.Println("processCommands:", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Error.Printf("processCommands - Got invalid HTTP response: %d\n", resp.StatusCode)
			continue
		}

	}
}

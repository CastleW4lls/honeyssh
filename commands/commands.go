package commands

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/sec51/honeyssh/log"
)

var segFault = []byte("Segmentiation fault\n")
var cmdNotFound = "%s: command not found\n"

var supportedCommands = []string{"wget", "curl", "lsb_release", "ls", "ifconfig", "netstat", "route", "cat", "dd", "sed", "grep", "ps",
	"vi", "vim", "nano", "env", "set", "echo", "sudo", "ip", "ping", "telnet", "apt", "aptitude", "ifdown", "ifup"}

func ParseCommand(cmd string) []string {
	return strings.Fields(cmd)
}

func ReadCommandOutput(cmd string, params []string) [][]byte {
	var output [][]byte

	if !isValidCommand(cmd) {
		err := []byte(fmt.Sprintf(cmdNotFound, cmd))
		output = append(output, err)
		return output
	}

	if params == nil || len(params) == 0 {
		if data, err := ioutil.ReadFile("static/" + cmd + ".txt"); err != nil {
			log.Error.Println("Error reading the command file:", cmd, err)
			output = append(output, segFault)
			return output
		} else {
			lines := bytes.Split(data, []byte("\n"))
			return lines
		}
	}

	switch cmd {
	case "wget":
		if commandContains(params, "-V") || commandContains(params, "--version") {
			return readCmdVersion(cmd)
		}
		if commandContains(params, "-h") || commandContains(params, "--help") {
			return readCmdHelp(cmd)
		}
	case "curl":
		if commandContains(params, "-V") || commandContains(params, "--version") {
			return readCmdVersion(cmd)
		}
		if commandContains(params, "--help") {
			return readCmdHelp(cmd)
		}

	case "lsb_release":
		if commandContains(params, "-v") || commandContains(params, "--version") {
			return readCmdVersion(cmd)
		}

		if commandContains(params, "-h") || commandContains(params, "--help") {
			return readCmdHelp(cmd)
		}

		if commandContains(params, "-a") || commandContains(params, "--all") {
			return readSpecificCmd("lsb_release_all.txt")
		}
	}

	output = append(output, segFault)
	return output

}

func readCmdVersion(cmd string) [][]byte {
	var output [][]byte
	if data, err := ioutil.ReadFile("static/" + cmd + "-version.txt"); err != nil {
		log.Error.Println("Error reading the command file:", cmd, err)
		output = append(output, segFault)
		return output
	} else {
		lines := bytes.Split(data, []byte("\n"))
		return lines
	}
}

func readCmdHelp(cmd string) [][]byte {
	var output [][]byte
	if data, err := ioutil.ReadFile("static/" + cmd + "-help.txt"); err != nil {
		log.Error.Println("Error reading the command file:", cmd, err)
		output = append(output, segFault)
		return output
	} else {
		lines := bytes.Split(data, []byte("\n"))
		return lines
	}
}

func readSpecificCmd(file string) [][]byte {
	var output [][]byte
	if data, err := ioutil.ReadFile("static/" + file); err != nil {
		log.Error.Println("Error reading the command file:", file, err)
		output = append(output, segFault)
		return output
	} else {
		lines := bytes.Split(data, []byte("\n"))
		return lines
	}
}

func commandContains(params []string, param string) bool {
	for _, elem := range params {
		if elem == param {
			return true
		}
	}

	return false
}

func isValidCommand(cmd string) bool {
	for _, c := range supportedCommands {
		if c == cmd {
			return true
		}
	}

	return false
}

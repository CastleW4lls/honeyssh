package sshd

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"syscall"
	"unsafe"
	//"io"
	//"sync"

	//"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/sec51/honeyssh/commands"
	"github.com/sec51/honeyssh/log"
	"github.com/sec51/honeyssh/models"
	"github.com/sec51/honeyssh/processing"
)

type sshd struct {
	config         *ssh.ServerConfig
	host           string
	port           string
	hostname       string
	user           string
	pass           string
	bruteforce     chan models.BruteforceAttack
	commands       chan models.Command
	dataProcessing processing.ProcessingService
}

type BruteforceAttack struct {
	Ip       string
	User     string
	Password string
}

func (sshServer *sshd) Start() {
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	sshServer.config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", sshServer.host, sshServer.port))
	if err != nil {
		log.Error.Println("FATAL: Failed to listen for connection on host", sshServer.host, "and port", sshServer.port)
		return
	}
	log.Info.Println("Listening for connection on host", sshServer.host, "and port", sshServer.port)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Error.Println("Failed to accept incoming SSH connection")
			continue
		}

		go sshServer.handleConnection(nConn)
	}
}

func NewSSHServer(host, port, hostname, user, password string) *sshd {
	sshdServer := new(sshd)

	sshdServer.commands = make(chan models.Command)
	sshdServer.bruteforce = make(chan models.BruteforceAttack)

	// attach the data processing and start it
	sshdServer.dataProcessing = processing.NewProcessingService(sshdServer.bruteforce, sshdServer.commands)
	sshdServer.dataProcessing.Start()

	if host == "" {
		host = "0.0.0.0"
	}
	sshdServer.host = host
	sshdServer.port = port
	sshdServer.user = user
	sshdServer.pass = password

	if hostname == "" {
		hostname = "localhost.localdomain"
	}
	sshdServer.hostname = hostname

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())

			if subtle.ConstantTimeCompare([]byte(c.User()), []byte(user)) == 1 && subtle.ConstantTimeCompare(pass, []byte(password)) == 1 {
				sshdServer.bruteforce <- models.MakeBruteforceAttack(ip, c.User(), string(pass), true)
				return nil, nil
			}

			sshdServer.bruteforce <- models.MakeBruteforceAttack(ip, c.User(), string(pass), false)
			log.Error.Printf("%s: Password rejected for %q with password %s\n", c.RemoteAddr().String(), c.User(), string(pass))

			return nil, fmt.Errorf("Password rejected for %q with password %s\n", c.User(), string(pass))
		},
	}

	sshdServer.config = config

	return sshdServer

}

func (sshServer *sshd) handleConnection(nConn net.Conn) {

	// get the client remote address
	clientId := nConn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(clientId)

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, sshServer.config)
	if err != nil {
		sshServer.bruteforce <- models.MakeBruteforceAttack(ip, "handshake", "handshake", false)
		log.Error.Println(clientId, "Failed to handshake", err)
		return
	}
	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Error.Println(clientId, "Could not accept channel.", err)
			return
		}

		prompt := fmt.Sprintf("%s@%s:/$ ", sshServer.user, sshServer.hostname)

		term := terminal.NewTerminal(channel, prompt)
		term.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
			//fmt.Printf("ACC: %v, %v, %s[%v]\n", line, pos, string(key), key)
			if key == 3 {
				fmt.Printf("ACC: %v, %v, %s[%v]\n", line, pos, string(key), key)
				newPrompt := "\r\n" + prompt
				return newPrompt, len(newPrompt), true
			}

			return line, pos, false

		}

		// Prepare teardown function
		// close := func() {
		// 	channel.Close()
		// 	// _, err := bash.Process.Wait()
		// 	// if err != nil {
		// 	// 	log.Printf("Failed to exit bash (%s)", err)
		// 	// }
		// 	log.Info.Println("Session closed")
		// }

		// ptyFd, _, err := pty.Open()
		// if err != nil {
		// 	log.Error.Println("Error while creating pty", err)
		// 	return
		// }

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				case "shell":
					ok = true
					if len(req.Payload) > 0 {
						// We don't accept any
						// commands, only the
						// default shell.
						ok = false
					}
					break
				case "pty-req":
					termLen := req.Payload[3]
					// fmt.Printf("%d\n", termLen)
					w, h := parseDims(req.Payload[termLen+4:])
					term.SetSize(w, h)
					// fmt.Printf("h:%d - w:%d \n", h, w)
					// SetWinsize(ptyFd.Fd(), w, h)
					//Responding true (OK) here will let the client
					//know we have a pty ready for input
					ok = true
					// if err := req.Reply(true, nil); err != nil {
					// 	log.Error.Println("Error responsing to tty request", err)
					// }

					break
				case "window-change":
					w, h := parseDims(req.Payload)
					term.SetSize(w, h)
					// SetWinsize(ptyFd.Fd(), w, h)
					ok = true

				}
				req.Reply(ok, nil)
			}
		}(requests)

		// modes := ssh.TerminalModes{
		// 	ssh.ECHO:          0,     // disable echoing
		// 	ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		// 	ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		// }

		// //pipe session to bash and visa-versa
		// var once sync.Once
		// go func() {
		// 	io.Copy(channel, ptyFd)
		// 	once.Do(close)
		// }()
		// go func() {
		// 	io.Copy(ptyFd, channel)
		// 	once.Do(close)
		// }()
		// if err := newChannel .RequestPty("xterm", 80, 40, modes); err != nil {
		// 	session.Close()
		// 	return nil, fmt.Errorf("request for pseudo terminal failed: %s", err)
		// }
		//terminal.NewTerminal(c, prompt)

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				fmt.Println(line, err)
				if err != nil {
					break
				}
				if line == "" || line == prompt || line == "\r\n"+prompt {
					continue
				}

				line = strings.Replace(line, prompt, "", -1)
				line = strings.TrimSpace(line)

				log.Info.Printf("%s: command: %s", clientId, line)
				sshServer.commands <- models.MakeCommand(ip, line)

				// exit the shell
				if line == "exit" {
					return
				}

				parsedCmd := commands.ParseCommand(line)

				lines := commands.ReadCommandOutput(parsedCmd[0], parsedCmd[1:])
				for _, line := range lines {
					term.Write(line)
					term.Write([]byte("\n\r"))
				}

			}
		}()
	}
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (int, int) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return int(w), int(h)
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

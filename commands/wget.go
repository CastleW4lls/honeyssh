package commands

import (
	"bytes"
)

func Wget() []byte {

	var buffer bytes.Buffer

	buffer.WriteString("wget: missing URL\n")
	buffer.WriteString("Usage: wget [OPTION]... [URL]...\n\n")
	buffer.WriteString("Try `wget --help' for more options.`\n")

	return buffer.Bytes()

}

// func WgetHelp() string {

// }

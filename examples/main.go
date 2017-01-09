package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/creack/sshproxy"
	"golang.org/x/crypto/ssh"
)

func main() {
	listen := flag.String("listen", ":2022", "listen address")
	dest := flag.String("dest", ":22", "destination address")
	key := flag.String("key", "host_key", "rsa key to use")
	flag.Parse()

	privateBytes, err := ioutil.ReadFile(*key)
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	sessions := map[net.Addr]map[string]interface{}{}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			fmt.Printf("Login attempt: %s, user %s password: %s\n", c.RemoteAddr(), c.User(), string(pass))

			sessions[c.RemoteAddr()] = map[string]interface{}{
				"username": c.User(),
				"password": string(pass),
			}

			clientConfig := &ssh.ClientConfig{
				User: c.User(),
				Auth: []ssh.AuthMethod{
					ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
						if len(questions) == 1 && questions[0] == "Password:" {
							return []string{string(pass)}, nil
						}
						return []string{}, nil
					}),
				},
			}
			client, err := ssh.Dial("tcp", *dest, clientConfig)
			if err != nil {
				return nil, err
			}
			sessions[c.RemoteAddr()]["client"] = client
			return nil, nil
		},
	}
	config.AddHostKey(private)

	log.Fatal(sshproxy.ListenAndServe(*listen, config, func(c ssh.ConnMetadata) (*ssh.Client, error) {
		meta, ok := sessions[c.RemoteAddr()]
		if !ok {
			return nil, fmt.Errorf("session not found")
		}
		client := meta["client"].(*ssh.Client)
		fmt.Printf("Connection accepted from: %s", c.RemoteAddr())
		return client, nil
	}, nil, nil))
}

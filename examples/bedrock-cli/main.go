// Command bedrock-cli is a small interactive client for exercising a Bedrock
// system from the command line: authenticate, heartbeat, fetch variables,
// and download Invisible Folder files.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	bedrock "github.com/systemlocker/system-locker-bedrock-go"
)

func main() {
	systemID := flag.String("system", "", "20-character system ID")
	signingKey := flag.String("signing-key", "", "base64url raw 32-byte Ed25519 public key")
	baseURL := flag.String("base-url", "https://systemlocker.net", "System Locker base URL")
	beatRate := flag.Int("beat-rate", 30, "heartbeat interval in seconds")
	flag.Parse()

	if *systemID == "" || *signingKey == "" {
		fmt.Fprintln(os.Stderr, "usage: bedrock-cli -system <id> -signing-key <key> [key|user]")
		os.Exit(2)
	}

	config := bedrock.DefaultConfig()
	config.SystemID = *systemID
	config.SigningPublicKey = *signingKey
	config.BaseURL = *baseURL
	config.BeatRate = time.Duration(*beatRate) * time.Second

	client, err := bedrock.NewClient(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	defer client.Shutdown()
	client.OnHeartbeatFailure(func(failure bedrock.HeartbeatFailure) {
		fmt.Println("[heartbeat failed]", failure.Error.Kind, failure.Error.Message)
		os.Exit(3)
	})

	ctx := context.Background()
	reader := bufio.NewReader(os.Stdin)

	var authErr error
	if flag.Arg(0) == "user" {
		fmt.Print("username: ")
		username, _ := reader.ReadString('\n')
		fmt.Print("password: ")
		password, _ := reader.ReadString('\n')
		var result bedrock.AuthenticationResult
		result, authErr = client.AuthenticateWithPassword(ctx, strings.TrimSpace(username), strings.TrimSpace(password), bedrock.InitializationOptions{RequestInvisibleFolderToken: true})
		printResult(result)
	} else {
		fmt.Print("license key: ")
		key, _ := reader.ReadString('\n')
		var result bedrock.AuthenticationResult
		result, authErr = client.AuthenticateWithKey(ctx, strings.TrimSpace(key), bedrock.InitializationOptions{RequestInvisibleFolderToken: true})
		printResult(result)
	}
	if authErr != nil {
		fmt.Fprintln(os.Stderr, "authentication:", authErr)
		os.Exit(1)
	}

	fmt.Println("commands: beat | var <name> | if-download <referenceId> <file> | status | quit")
	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "beat":
			response, err := client.HeartbeatNow(ctx, bedrock.HeartbeatOptions{RequestInvisibleFolderToken: true})
			if err != nil {
				fmt.Println("beat failed:", err)
				continue
			}
			fmt.Println("beat:", response.ResponseCodeName)
		case "var":
			if len(fields) != 2 {
				fmt.Println("usage: var <name>")
				continue
			}
			response, err := client.HeartbeatNow(ctx, bedrock.HeartbeatOptions{})
			_ = response
			if err != nil {
				fmt.Println("beat failed:", err)
				continue
			}
			fmt.Println("use InitializationOptions.Variables on authenticate (variables ride init/beat responses)")
		case "if-download":
			if len(fields) != 3 {
				fmt.Println("usage: if-download <referenceId> <file>")
				continue
			}
			if err := client.InvisibleFolder().DownloadToFile(ctx, fields[1], fields[2]); err != nil {
				fmt.Println("download failed:", err)
				continue
			}
			fmt.Println("saved", fields[2])
		case "status":
			fmt.Printf("authenticated=%v heartbeats=%d ifToken=%v\n",
				client.IsAuthenticated(), client.HeartbeatCount(), client.InvisibleFolder().HasToken())
		case "quit":
			return
		}
	}
}

func printResult(result bedrock.AuthenticationResult) {
	fmt.Println("response:", result.Response.ResponseCodeName, "-", result.Response.HumanResponse)
	for name, variable := range result.Response.Variables {
		if variable.Found {
			fmt.Printf("variable %s = %q\n", name, variable.Value)
		} else {
			fmt.Printf("variable %s = <absent>\n", name)
		}
	}
}

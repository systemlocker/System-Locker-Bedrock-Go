// Command quickstart shows the smallest working Bedrock integration.
package main

import (
	"context"
	"fmt"
	"time"

	bedrock "github.com/systemlocker/system-locker-bedrock-go"
	"github.com/systemlocker/system-locker-bedrock-go/hwid"
)

func main() {
	device, err := hwid.DeviceHWID()
	if err != nil {
		fmt.Println("Falling back to a developer-supplied HWID:", err)
		device = "my-own-stable-identifier"
	}

	config := bedrock.DefaultConfig()
	config.SystemID = "abcdefghijklmnopqrst"                 // from the dashboard
	config.SigningPublicKey = "base64url-ed25519-public-key" // from the dashboard
	config.HWID = device
	config.Version = "1.0.0"

	client, err := bedrock.NewClient(config)
	if err != nil {
		panic(err)
	}
	client.OnHeartbeatFailure(func(failure bedrock.HeartbeatFailure) {
		fmt.Println("session ended:", failure.Error.Message)
		// Save state and exit; the license is no longer verified as live.
	})

	result, err := client.AuthenticateWithKey(context.Background(), "SL-XXXX-XXXX-XXXX", bedrock.InitializationOptions{})
	if err != nil {
		panic(err)
	}
	if !result.SessionStarted {
		fmt.Println("rejected:", result.Response.HumanResponse)
		return
	}

	fmt.Println("authenticated; heartbeating every", config.BeatRate)
	time.Sleep(90 * time.Second) // your protected application logic

	client.Shutdown()
}

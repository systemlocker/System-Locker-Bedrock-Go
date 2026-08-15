package bedrock

import (
	"context"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const clockJumpTolerance = 2 * time.Second

// HeartbeatFailure is delivered to the OnHeartbeatFailure hook exactly once
// per session, when the session first fails.
type HeartbeatFailure struct {
	Error               *Error
	Response            *Response
	CompletedHeartbeats uint64
}

// session owns one authenticated Bedrock session: the rotating token, the
// background heartbeat loop, and local tamper detection.
type session struct {
	client *Client

	tokenMutex   sync.Mutex
	token        string
	requestMutex sync.Mutex

	hookMutex sync.Mutex
	hook      func(HeartbeatFailure)

	cancel    context.CancelFunc
	done      chan struct{}
	started   atomic.Bool
	alive     atomic.Bool
	completed atomic.Uint64
	stopOnce  sync.Once
}

func newSession(client *Client, token string, hook func(HeartbeatFailure)) *session {
	s := &session{
		client: client,
		token:  token,
		hook:   hook,
		done:   make(chan struct{}),
	}
	s.alive.Store(true)
	return s
}

// start launches the background heartbeat loop.
func (s *session) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.started.Store(true)
	go s.run(ctx)
}

// stop halts the loop without firing the failure hook.
func (s *session) stop() {
	s.stopOnce.Do(func() {
		s.alive.Store(false)
		if s.cancel != nil {
			s.cancel()
		}
	})
}

// wait blocks until the heartbeat goroutine exits; a no-op when the loop
// was never started.
func (s *session) wait() {
	if s.started.Load() {
		<-s.done
	}
}

func (s *session) aliveValue() bool { return s.alive.Load() }

func (s *session) setHook(hook func(HeartbeatFailure)) {
	s.hookMutex.Lock()
	defer s.hookMutex.Unlock()
	s.hook = hook
}

// fail marks the session dead and fires the hook once.
func (s *session) fail(err *Error, response *Response) {
	wasAlive := s.alive.Swap(false)
	s.stop()
	if !wasAlive {
		return
	}
	s.hookMutex.Lock()
	hook := s.hook
	s.hookMutex.Unlock()
	if hook != nil {
		hook(HeartbeatFailure{Error: err, Response: response, CompletedHeartbeats: s.completed.Load()})
	}
}

// heartbeat performs one beat: challenge, POST (with one transport retry),
// verification, token rotation.
func (s *session) heartbeat(ctx context.Context, options HeartbeatOptions) (Response, error) {
	s.requestMutex.Lock()
	defer s.requestMutex.Unlock()
	if !s.aliveValue() {
		return Response{}, fail(ErrSessionTerminated, "Bedrock session is not active.")
	}

	challenge, err := generateChallenge()
	if err != nil {
		s.fail(asError(err), nil)
		return Response{}, err
	}

	s.tokenMutex.Lock()
	token := s.token
	s.tokenMutex.Unlock()

	fields := url.Values{
		"session_token": {token},
		"system":        {s.client.config.SystemID},
		"challenge":     {challenge},
	}
	if options.RequestInvisibleFolderToken {
		fields.Set("init-if", "true")
	}

	endpoint := s.client.endpoint(s.client.config.BaseURL, beatPath)
	headers := s.client.signedHeaders()
	httpResponse := s.client.transport().PostForm(ctx, endpoint, fields, headers)
	// A transport failure may mean the server committed the rotation but the
	// response was lost. Repeat the exact token/challenge once so Bedrock can
	// return its cached signed response.
	if httpResponse.Err != nil {
		httpResponse = s.client.transport().PostForm(ctx, endpoint, fields, headers)
	}

	if !httpResponse.OK() {
		var message string
		if httpResponse.Err != nil {
			message = "Bedrock heartbeat transport failed: " + httpResponse.Err.Error()
		} else {
			message = "Bedrock heartbeat returned HTTP " + strconv.Itoa(httpResponse.StatusCode) + "."
		}
		err := fail(ErrTransport, "%s", message)
		s.fail(err, nil)
		return Response{}, err
	}

	response, verifyErr := VerifySignedResponse(s.client.config, httpResponse, challenge, s.client.now())
	if verifyErr != nil {
		if bedrockErr := asError(verifyErr); bedrockErr.Kind == ErrUnsignedResponse {
			response, verifyErr = ParseUnsignedRevocation(s.client.config, httpResponse, challenge, s.client.now())
		}
	}
	if verifyErr != nil {
		err := asError(verifyErr)
		s.fail(err, nil)
		return Response{}, err
	}

	if response.Code != CodeOK || !response.Authed || response.SessionToken == "" {
		err := fail(ErrSessionTerminated, "%s", response.TerminationMessage)
		if err.Message == "" {
			err.Message = response.HumanResponse
		}
		s.fail(err, &response)
		return response, nil
	}
	if len(response.SessionToken) < 4 || response.SessionToken[:4] != "BRF_" {
		err := fail(ErrInvalidPayload, "Bedrock heartbeat returned an invalid rotated token format.")
		s.fail(err, nil)
		return Response{}, err
	}

	s.tokenMutex.Lock()
	s.token = response.SessionToken
	s.tokenMutex.Unlock()
	s.completed.Add(1)
	return response, nil
}

// run drives the automatic heartbeat loop with local clock tamper detection.
func (s *session) run(ctx context.Context) {
	defer close(s.done)

	previousSteady := time.Now()
	previousWall := wallClockNow()
	ticker := time.NewTicker(s.client.config.BeatRate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		currentSteady := time.Now()
		currentWall := wallClockNow()
		steadyElapsed := currentSteady.Sub(previousSteady)
		wallElapsed := currentWall.Sub(previousWall)
		skew := steadyElapsed - wallElapsed
		if skew < 0 {
			skew = -skew
		}
		if skew > clockJumpTolerance {
			s.fail(fail(ErrLocalFailure, "Local clock changed unexpectedly during a Bedrock session."), nil)
			return
		}
		previousSteady = currentSteady
		previousWall = currentWall

		response, err := s.heartbeat(ctx, HeartbeatOptions{})
		if err != nil || !s.aliveValue() {
			return
		}
		_ = response
	}
}

// wallClockNow strips the monotonic reading so subtraction uses wall time.
func wallClockNow() time.Time {
	return time.Now().Round(0)
}

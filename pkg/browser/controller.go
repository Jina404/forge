package browser

import (
	"fmt"
	"time"
)

// Controller tracks browser sessions managed outside the Go process.
type Controller struct{}

func NewController() *Controller { return &Controller{} }

func (c *Controller) StartSession(targetURL string) (Session, error) {
	if targetURL == "" {
		return Session{}, fmt.Errorf("target URL is required")
	}
	return Session{
		ID:        fmt.Sprintf("br-%d", time.Now().UnixNano()),
		TargetURL: targetURL,
		CreatedAt: time.Now().UTC(),
		Active:    true,
	}, nil
}

func (c *Controller) EndSession(session Session) Session {
	session.Active = false
	return session
}

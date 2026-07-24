package browser

import "time"

// Session describes browser automation state.
type Session struct {
	ID        string
	TargetURL string
	CreatedAt time.Time
	Active    bool
}

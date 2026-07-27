package transport

// SMSSendRequest asks the agent to send a text message via the companion app.
type SMSSendRequest struct {
	Token string `json:"token"`
	To    string `json:"to"`
	Body  string `json:"body"`
}

// SMSThreadRequest asks the agent to list SMS conversation threads.
type SMSThreadRequest struct {
	Token string `json:"token"`
	Limit int    `json:"limit,omitempty"`
}

// SMSMessagesRequest asks the agent to list messages within one thread.
type SMSMessagesRequest struct {
	Token    string `json:"token"`
	ThreadID string `json:"threadId"`
	Limit    int    `json:"limit,omitempty"`
}

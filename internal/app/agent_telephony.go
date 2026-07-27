package app

import (
	"context"
	"time"

	"github.com/austinkregel/compute-agent/pkg/transport"
)

const telephonyRequestTimeout = 20 * time.Second

func (a *Agent) handleSMSSend(req transport.SMSSendRequest) {
	if a.telephony == nil {
		_ = a.transport.Emit("sms_send_result", map[string]any{
			"token": req.Token, "error": "telephony not configured on this agent",
		})
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), telephonyRequestTimeout)
	defer cancel()

	result, err := a.telephony.SendSMS(ctx, req.To, req.Body)
	if err != nil {
		_ = a.transport.Emit("sms_send_result", map[string]any{
			"token": req.Token, "to": req.To, "error": err.Error(),
		})
		return
	}
	resp := map[string]any{"token": req.Token, "to": req.To}
	for k, v := range result {
		resp[k] = v
	}
	_ = a.transport.Emit("sms_send_result", resp)
}

func (a *Agent) handleSMSThreadRequest(req transport.SMSThreadRequest) {
	if a.telephony == nil {
		_ = a.transport.Emit("sms_thread_response", map[string]any{
			"token": req.Token, "error": "telephony not configured on this agent", "threads": []any{},
		})
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), telephonyRequestTimeout)
	defer cancel()

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	threads, err := a.telephony.ListThreads(ctx, limit)
	if err != nil {
		_ = a.transport.Emit("sms_thread_response", map[string]any{
			"token": req.Token, "error": err.Error(), "threads": []any{},
		})
		return
	}
	_ = a.transport.Emit("sms_thread_response", map[string]any{
		"token": req.Token, "threads": threads,
	})
}

func (a *Agent) handleSMSMessagesRequest(req transport.SMSMessagesRequest) {
	if a.telephony == nil {
		_ = a.transport.Emit("sms_messages_response", map[string]any{
			"token": req.Token, "threadId": req.ThreadID,
			"error": "telephony not configured on this agent", "messages": []any{},
		})
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), telephonyRequestTimeout)
	defer cancel()

	limit := req.Limit
	if limit <= 0 {
		limit = 200
	}
	messages, err := a.telephony.ListMessages(ctx, req.ThreadID, limit)
	if err != nil {
		_ = a.transport.Emit("sms_messages_response", map[string]any{
			"token": req.Token, "threadId": req.ThreadID, "error": err.Error(), "messages": []any{},
		})
		return
	}
	_ = a.transport.Emit("sms_messages_response", map[string]any{
		"token": req.Token, "threadId": req.ThreadID, "messages": messages,
	})
}

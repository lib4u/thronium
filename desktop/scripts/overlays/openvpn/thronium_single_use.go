package openvpn

// reserveSingleUseAuth protects both fresh sessions and renegotiated TLS key
// methods. Transport retry, challenge retry, and server-requested rekey must not
// resend a code embedded in credentials. A new explicit client gets a new code.
// Normal credentials retain the upstream behavior.
func (c *Client) reserveSingleUseAuth() error {
	if !c.options.Authentication.SingleUse {
		return nil
	}
	c.authentication.access.Lock()
	defer c.authentication.access.Unlock()
	if c.authentication.singleUseSent {
		return &AuthFailedTerminalError{Reason: "single-use credentials already sent; reconnect with a fresh code"}
	}
	c.authentication.singleUseSent = true
	return nil
}

package winservice

import "errors"

// samePublisher decides whether a client may talk to a service by their
// signatures: an unsigned service (a development or test build) checks
// nothing more than the path, a signed one only accepts a client signed by
// the same publisher.
func samePublisher(service string, serviceErr error, client string, clientErr error) error {
	if serviceErr != nil {
		return nil
	}
	if clientErr != nil || client != service {
		return errors.New("client is not signed by the service's publisher")
	}
	return nil
}

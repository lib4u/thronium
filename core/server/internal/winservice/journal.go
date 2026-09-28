package winservice

import (
	"encoding/json"
	"errors"
)

// journal is what the service must undo if it, the application or the
// machine stops without a clean Stop: the worker it started and whether it
// changed any interface's DNS servers.
type journal struct {
	Version       int    `json:"version"`
	WorkerPID     uint32 `json:"workerPid"`
	WorkerCreated uint64 `json:"workerCreated"`
	SystemDNS     bool   `json:"systemDns"`
}

const journalVersion = 1

func decodeJournal(data []byte) (journal, error) {
	var j journal
	if len(data) > 4096 || json.Unmarshal(data, &j) != nil || j.Version != journalVersion {
		return journal{}, errors.New("tun_journal_untrusted")
	}
	return j, nil
}

func encodeJournal(j *journal) ([]byte, error) {
	return json.Marshal(j)
}

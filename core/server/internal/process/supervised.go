package process

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/shlex"
)

const GuardianArgument = "--thronium-extra-guardian"
const ProtocolVersion = uint32(1)

// A valid 1 MiB UTF-8 config can expand sixfold when JSON-escaped.
const maxControlFrame = 8 * 1024 * 1024

// Spec never belongs in public status/logs. It crosses only an inherited private fd.
type Spec struct {
	Path      string   `json:"path"`
	Args      []string `json:"args"`
	Config    string   `json:"config"`
	NoLogs    bool     `json:"noLogs"`
	Address   string   `json:"address"`
	Port      uint32   `json:"port"`
	TimeoutMS uint32   `json:"timeoutMs"`
}

type Status struct {
	State    string `json:"state"`
	Instance string `json:"instance,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ExitCode *int32 `json:"exitCode,omitempty"`
}

func ParseSpec(path, rawArgs, config string, noLogs bool, version uint32, address string, port, timeout uint32) (Spec, error) {
	if version != ProtocolVersion {
		return Spec{}, errors.New("external_core_version")
	}
	if len(rawArgs) > 32*1024 || !utf8.ValidString(rawArgs) || strings.IndexByte(rawArgs, 0) >= 0 {
		return Spec{}, errors.New("external_core_arguments_invalid")
	}
	args, err := shlex.Split(rawArgs)
	if err != nil {
		return Spec{}, errors.New("external_core_arguments_invalid")
	}
	spec := Spec{Path: path, Args: args, Config: config, NoLogs: noLogs, Address: address, Port: port, TimeoutMS: timeout}
	if err = spec.validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func (s Spec) validate() error {
	if len(s.Path) == 0 || len(s.Path) > 4096 || !utf8.ValidString(s.Path) || strings.IndexFunc(s.Path, unicode.IsControl) >= 0 || !filepath.IsAbs(s.Path) {
		return errors.New("external_core_path_invalid")
	}
	if s.Address != "127.0.0.1" || s.Port < 1024 || s.Port > 65535 || s.TimeoutMS != 10000 {
		return errors.New("external_core_options_invalid")
	}
	if len(s.Config) > 1024*1024 || !utf8.ValidString(s.Config) || strings.IndexByte(s.Config, 0) >= 0 {
		return errors.New("external_core_config_invalid")
	}
	if len(s.Args) > 128 {
		return errors.New("external_core_arguments_invalid")
	}
	count, size := 0, 0
	for _, arg := range s.Args {
		if len(arg) > 32*1024 || !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("external_core_arguments_invalid")
		}
		size += len(arg)
		count += strings.Count(arg, "%s")
	}
	if size > 32*1024 {
		return errors.New("external_core_arguments_invalid")
	}
	if count > 1 || (count == 0 && s.Config != "") {
		return errors.New("external_core_config_placeholder")
	}
	file, err := os.Stat(s.Path)
	if err != nil || !file.Mode().IsRegular() {
		return errors.New("external_core_executable_unavailable")
	}
	return runnable(s.Path, file)
}

// All percent characters except the one documented placeholder are literal.
func (s Spec) arguments(path string) []string {
	args := append([]string{}, s.Args...)
	for i, arg := range args {
		if strings.Contains(arg, "%s") {
			args[i] = strings.Replace(arg, "%s", path, 1)
			break
		}
	}
	return args
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > maxControlFrame {
		return errors.New("external_core_control_invalid")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(b)))
	if err = writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readFrame(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > maxControlFrame {
		return errors.New("external_core_control_invalid")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return errors.New("external_core_control_invalid")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("external_core_control_invalid")
	}
	return nil
}

func supervisedEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "THRONE") || strings.HasPrefix(upper, "THRONIUM") || strings.HasSuffix(upper, "_PROXY") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// The endpoint speaks SOCKS5 without authentication. Callers check that the
// listener belongs to the supervised tree before and after asking.
func socksAnswers(spec Spec) bool {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(spec.Address, strconv.Itoa(int(spec.Port))), 150*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	var response [2]byte
	_, err = io.ReadFull(conn, response[:])
	return err == nil && response == [2]byte{5, 0}
}

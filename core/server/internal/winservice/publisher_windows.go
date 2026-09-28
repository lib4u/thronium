//go:build windows

package winservice

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust                         = windows.NewLazySystemDLL("wintrust.dll")
	procProvDataFromStateData        = wintrust.NewProc("WTHelperProvDataFromStateData")
	procProvSignerFromChain          = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	errUnsigned                      = errors.New("no trusted signature")
	certNameRDNType           uint32 = 2
	certX500NameStr           uint32 = 3
)

// The leading fields of CRYPT_PROVIDER_SGNR and CRYPT_PROVIDER_CERT
// (wintrust.h), up to what is read here.
type providerSigner struct {
	size       uint32
	verifyAsOf windows.Filetime
	certCount  uint32
	certs      *providerCert
}

type providerCert struct {
	size uint32
	cert *windows.CertContext
}

// publisher is the subject of the certificate whose trusted Authenticode
// signature covers path; errUnsigned when there is none.
func publisher(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name}
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verified := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	}()
	if verified != nil {
		return "", errUnsigned
	}
	if procProvDataFromStateData.Find() != nil || procProvSignerFromChain.Find() != nil {
		return "", errUnsigned
	}
	provider, _, _ := procProvDataFromStateData.Call(uintptr(data.StateData))
	if provider == 0 {
		return "", errUnsigned
	}
	signerPointer, _, _ := procProvSignerFromChain.Call(provider, 0, 0, 0)
	if signerPointer == 0 {
		return "", errUnsigned
	}
	// The pointer comes from wintrust as an integer; read it as one.
	signer := *(**providerSigner)(unsafe.Pointer(&signerPointer))
	if signer.certCount == 0 || signer.certs == nil || signer.certs.cert == nil {
		return "", errUnsigned
	}
	buffer := make([]uint16, 1024)
	n := windows.CertGetNameString(signer.certs.cert, certNameRDNType, 0,
		unsafe.Pointer(&certX500NameStr), &buffer[0], uint32(len(buffer)))
	if n <= 1 {
		return "", errUnsigned
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

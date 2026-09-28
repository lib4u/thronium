//go:build !linux && !windows

package process

import "errors"

func SupervisionSupported() bool { return false }
func GuardianMain() bool         { return false }

type Supervised struct{}

func NewSupervised(Spec) *Supervised    { return &Supervised{} }
func (*Supervised) Start() error        { return errors.New("external_core_unavailable") }
func (*Supervised) Stop() error         { return nil }
func (*Supervised) Status() Status      { return Status{State: "inactive"} }
func Preflight(Spec, *Supervised) error { return errors.New("external_core_unavailable") }

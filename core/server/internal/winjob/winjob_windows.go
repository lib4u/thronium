//go:build windows

// Package winjob keeps a process tree in a job object that only its creator
// holds and that kills every member when that handle closes.
package winjob

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The handle is not inheritable, so no member can keep the job alive.
func New() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// Adopt puts the suspended process into the job and only then lets it run.
// Its PID cannot be reused meanwhile: exec still holds the process handle.
func Adopt(job windows.Handle, pid uint32) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	err = windows.AssignProcessToJobObject(job, process)
	_ = windows.CloseHandle(process)
	if err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	resumed := false
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		_, err = windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		if err != nil {
			return err
		}
		resumed = true
	}
	if !resumed {
		return errors.New("job_resume_failed")
	}
	return nil
}

// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, which x/sys/windows does not define.
type jobAccounting struct {
	TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime      int64
	TotalPageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
}

// terminate kills every member and reports whether the job is empty in time.
func Terminate(job windows.Handle) bool {
	_ = windows.TerminateJobObject(job, 1)
	deadline := time.Now().Add(time.Second)
	for {
		var info jobAccounting
		if windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil) != nil {
			return false
		}
		if info.ActiveProcesses == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

use super::*;

#[test]
fn handshake_is_versioned_fixed_length_and_rejects_malformed_tokens() {
    for data in [
        b"TPG1"
            .iter()
            .copied()
            .chain([b'a'; 32])
            .collect::<Vec<_>>(),
        vec![0; 36],
        b"TPG1abcdef".to_vec(),
        b"TPG1".iter().copied().chain([b'A'; 32]).collect(),
    ] {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&data).unwrap();
        drop(writer);
        assert_eq!(
            token(&mut reader).is_ok(),
            data.len() == 36 && data[4..] == [b'a'; 32]
        );
    }
}
#[test]
fn private_channel_distinguishes_disarm_eof_and_invalid_commands() {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) as i32 };
    assert!(raw >= 0);
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    for byte in [Some(b'D'), Some(b'X'), None] {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        if let Some(byte) = byte {
            writer.write_all(&[byte]).unwrap();
        }
        drop(writer);
        let result = wait_owner(&mut reader, &pidfd);
        match byte {
            Some(b'D') => assert!(!result.unwrap()),
            None => assert!(result.unwrap()),
            _ => assert!(result.is_err()),
        }
    }
}
#[test]
fn guardian_rejects_standard_fds_and_a_socket_created_by_itself() {
    assert!(authenticated_channel(0).is_err());
    let (_a, b) = UnixStream::pair().unwrap();
    assert!(authenticated_channel(b.as_raw_fd()).is_err());
    let f = tempfile::tempfile().unwrap();
    assert!(authenticated_channel(f.as_raw_fd()).is_err());
}

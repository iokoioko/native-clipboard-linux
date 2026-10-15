//! Cancellation also reaches blocking compression and extraction work.
use std::{
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
#[derive(Clone, Default)]
pub struct Token(Arc<AtomicBool>);
impl Token {
    pub fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Relaxed) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "transfer cancelled",
            ))
        } else {
            Ok(())
        }
    }
}
pub struct Guard(pub Token);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0 .0.store(true, Ordering::Relaxed);
    }
}
pub struct Reader<R> {
    pub inner: R,
    pub token: Token,
}
impl<R: Read> Read for Reader<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.token.check()?;
        self.inner.read(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropped_owner_stops_blocking_copy() {
        let token = Token::default();
        let guard = Guard(token.clone());
        let mut reader = Reader {
            inner: &b"payload"[..],
            token,
        };
        drop(guard);
        let mut output = Vec::new();
        let error = std::io::copy(&mut reader, &mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(output.is_empty());
    }
}

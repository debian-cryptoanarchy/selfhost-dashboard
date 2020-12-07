use std::io::{self, BufRead};

pub trait BufReadExt: BufRead {
    fn read_line_max(&mut self, max: usize) -> io::Result<String> {
        let mut line = String::new();
        loop {
            let buf = self.fill_buf()?;
            if buf.is_empty() {
                return Ok(line);
            }
            let line_break_pos = buf.iter().position(|byte| *byte == b'\n');

            match line_break_pos {
                Some(pos) if line.len() + pos <= max => {
                    let decoded = std::str::from_utf8(&buf[..pos]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    line += decoded;
                    // Also consume the delimiter
                    self.consume(pos + 1);
                    return Ok(line);
                },
                None if line.len() + buf.len() <= max => {
                    let decoded = std::str::from_utf8(buf).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    line += decoded;
                    let len = buf.len();
                    self.consume(len);
                }
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }
}

impl<T: io::BufRead> BufReadExt for T {}

#[cfg(test)]
mod tests {
    use super::BufReadExt;

    #[test]
    fn read_line_max_below_limit_no_newline() {
        let mut input = b"test" as &[u8];
        let input_reader = &mut input;
        let line = input_reader.read_line_max(1024).unwrap();
        assert_eq!(line, "test");
        assert!(input_reader.read_line_max(1024).unwrap().is_empty());
    }

    #[test]
    fn read_line_max_below_limit_with_newline() {
        let mut input = b"test\nfoo" as &[u8];
        let input_reader = &mut input;
        let line = input_reader.read_line_max(1024).unwrap();
        assert_eq!(line, "test");
        assert_eq!(input_reader.read_line_max(1024).unwrap(), "foo");
    }

    #[test]
    fn read_line_max_exact_limit_no_newline() {
        let mut input = b"test" as &[u8];
        let input_reader = &mut input;
        let line = input_reader.read_line_max(input_reader.len()).unwrap();
        assert_eq!(line, "test");
        assert!(input_reader.read_line_max(1024).unwrap().is_empty());
    }

    #[test]
    fn read_line_max_exact_limit_with_newline() {
        let mut input = b"test\nfoo" as &[u8];
        let input_reader = &mut input;
        let line = input_reader.read_line_max(b"test".len()).unwrap();
        assert_eq!(line, "test");
        assert_eq!(input_reader.read_line_max(1024).unwrap(), "foo");
    }

    #[test]
    fn read_line_max_above_limit_no_newline() {
        let mut input = b"test" as &[u8];
        let input_reader = &mut input;
        let err = input_reader.read_line_max(input_reader.len() - 1).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_max_above_limit_with_newline() {
        let mut input = b"test" as &[u8];
        let input_reader = &mut input;
        let err = input_reader.read_line_max(b"test".len() - 1).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

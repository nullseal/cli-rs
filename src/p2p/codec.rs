//! P2P v2 binary DataChannel framing (pure, no I/O).
//!
//! Wire format (big-endian), byte-compatible with the web `lib/p2p/codec.ts`:
//!   chunk : [0x01][u64 chunkIndex][ciphertext bytes]
//!   end   : [0x02][u64 totalChunks]
//! `metadata` is a separate JSON *string* frame handled by the adapter, not here.

pub const FRAME_CHUNK: u8 = 0x01;
pub const FRAME_END: u8 = 0x02;

#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Chunk { index: u64, payload: &'a [u8] },
    End { total_chunks: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Empty,
    Short,
    UnknownType(u8),
}

/// `[0x01][u64 index][ciphertext]`
pub fn encode_chunk(index: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + ciphertext.len());
    out.push(FRAME_CHUNK);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// `[0x02][u64 totalChunks]`
pub fn encode_end(total_chunks: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(FRAME_END);
    out.extend_from_slice(&total_chunks.to_be_bytes());
    out
}

/// Decode one binary frame.
pub fn decode(frame: &[u8]) -> Result<Frame<'_>, DecodeError> {
    let &t = frame.first().ok_or(DecodeError::Empty)?;
    match t {
        FRAME_CHUNK => {
            if frame.len() < 9 {
                return Err(DecodeError::Short);
            }
            let index = u64::from_be_bytes(frame[1..9].try_into().unwrap());
            Ok(Frame::Chunk {
                index,
                payload: &frame[9..],
            })
        }
        FRAME_END => {
            if frame.len() < 9 {
                return Err(DecodeError::Short);
            }
            let total_chunks = u64::from_be_bytes(frame[1..9].try_into().unwrap());
            Ok(Frame::End { total_chunks })
        }
        other => Err(DecodeError::UnknownType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // ── Golden vectors (MUST stay byte-identical to user/src/lib/p2p/codec.test.ts) ──
    #[test]
    fn encode_chunk_golden_vectors() {
        assert_eq!(hex(&encode_chunk(0, &[0xaa, 0xbb, 0xcc])), "010000000000000000aabbcc");
        assert_eq!(hex(&encode_chunk(1, &[0xde, 0xad])), "010000000000000001dead");
        assert_eq!(hex(&encode_chunk(258, &[0x01])), "01000000000000010201");
    }

    #[test]
    fn encode_end_golden_vectors() {
        assert_eq!(hex(&encode_end(10)), "02000000000000000a");
        assert_eq!(hex(&encode_end(70)), "020000000000000046");
    }

    #[test]
    fn encode_chunk_header_layout() {
        let f = encode_chunk(0x0102030405, &[0x99]);
        assert_eq!(f[0], FRAME_CHUNK);
        assert_eq!(hex(&f[1..9]), "0000000102030405");
        assert_eq!(f[9], 0x99);
    }

    #[test]
    fn round_trip_chunk() {
        let payload = [1u8, 2, 3, 4, 5];
        match decode(&encode_chunk(42, &payload)).unwrap() {
            Frame::Chunk { index, payload: p } => {
                assert_eq!(index, 42);
                assert_eq!(p, &payload);
            }
            other => panic!("expected chunk, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_end() {
        assert_eq!(decode(&encode_end(6700)).unwrap(), Frame::End { total_chunks: 6700 });
    }

    #[test]
    fn chunk_with_empty_payload() {
        match decode(&encode_chunk(7, &[])).unwrap() {
            Frame::Chunk { index, payload } => {
                assert_eq!(index, 7);
                assert!(payload.is_empty());
            }
            other => panic!("expected chunk, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_frames() {
        assert_eq!(decode(&[]), Err(DecodeError::Empty));
        assert_eq!(decode(&[FRAME_CHUNK, 0, 0]), Err(DecodeError::Short));
        assert_eq!(decode(&[FRAME_END, 0, 0]), Err(DecodeError::Short));
        assert_eq!(decode(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DecodeError::UnknownType(0x09)));
    }
}

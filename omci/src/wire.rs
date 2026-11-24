// SPDX-License-Identifier: GPL-2.0-only

pub struct Writer {
    output: Vec<u8>,
}

impl Writer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
        }
    }

    pub fn u8(&mut self, value: u8) {
        self.output.push(value);
    }

    pub fn be16(&mut self, value: u16) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_network_order_values() {
        let mut writer = Writer::with_capacity(7);
        writer.u8(0x12);
        writer.be16(0x3456);
        writer.bytes(&[0x78, 0x9a]);
        assert_eq!(writer.into_vec(), [0x12, 0x34, 0x56, 0x78, 0x9a]);
    }
}

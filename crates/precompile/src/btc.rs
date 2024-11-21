use byteorder::{BigEndian, WriteBytesExt};
use tokio::runtime::Runtime;

use revm_primitives::{PrecompileOutput, PrecompileResult};

use crate::{Bytes, Error, HashMap};
use crate::btc_utilities::BitcoinRpcClient;

pub fn btc_header_n_run_rpc(input: &Bytes, client: &BitcoinRpcClient, gas_limit: u64, storage: &mut HashMap<Bytes, Bytes>) -> PrecompileResult {
    const BTC_HEADER_N_BASE: u64 = 6_000;
    if input.is_empty() || input.len() != 4 {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()));
    }

    if BTC_HEADER_N_BASE > gas_limit {
        return Err(Error::OutOfGas.into());
    }

    let height: u32 = ((input[0] as u32 & 0xFF) << 24)
        | ((input[1] as u32 & 0xFF) << 16)
        | ((input[2] as u32 & 0xFF) << 8)
        | (input[3] as u32 & 0xFF);

    let rt = Runtime::new().unwrap();

    let block_hash_result = rt.block_on(
        client.get_block_hash(height)
    );
    if block_hash_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()));
    }

    let block_hash = block_hash_result.unwrap();

    let block_header_result = rt.block_on(client.get_block_header(block_hash.to_string().as_str(), true));

    if block_header_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()));
    }

    let (block_header, height) = block_header_result.unwrap();

    let mut resp = Vec::new();

    resp.write_u32::<BigEndian>(height).unwrap();

    let binding = block_header.block_hash();
    let block_hash: &[u8] = binding.as_ref();

    resp.extend_from_slice(block_hash.iter().rev().copied().collect::<Vec<u8>>().as_slice());

    resp.write_u32::<BigEndian>(block_header.version.to_consensus() as u32).unwrap();

    let prev_blockhash: &[u8] = block_header.prev_blockhash.as_ref();

    resp.extend_from_slice(prev_blockhash.iter().rev().copied().collect::<Vec<u8>>().as_slice());

    let merkle_root: &[u8] = block_header.merkle_root.as_ref();

    resp.extend_from_slice(merkle_root.iter().rev().copied().collect::<Vec<u8>>().as_slice());
    resp.write_u32::<BigEndian>(block_header.time).unwrap();

    resp.write_u32::<BigEndian>(block_header.bits.to_consensus()).unwrap();

    resp.write_u32::<BigEndian>(block_header.nonce).unwrap();

    storage.insert(input.clone(), resp.clone().into());

    Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, resp.into()))
}

pub fn btc_tx_confirmations_run_rpc(input: &Bytes, client: &BitcoinRpcClient, gas_limit: u64, storage: &mut HashMap<Bytes, Bytes>) -> PrecompileResult {
    const BTC_TX_CONFIRMATIONS_BASE: u64 = 5_000;
    if input.is_empty() || input.len() != 32 {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    if BTC_TX_CONFIRMATIONS_BASE > gas_limit {
        return Err(Error::OutOfGas.into());
    }

    let rt = Runtime::new().unwrap();

    let tx_id_str = hex::encode(input);
    let raw_transaction_result = rt.block_on(
        client.get_raw_transaction(&tx_id_str,  None)
    );
    if raw_transaction_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    let (_, block_hash) = raw_transaction_result.unwrap();

    let block_header_result = rt.block_on(client.get_block_header(block_hash.to_string().as_str(), true));

    if block_header_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    let (_, height) = block_header_result.unwrap();
    let best_block_hash_result =  rt.block_on(client.get_best_block_hash());

    let best_block_hash = best_block_hash_result.unwrap();
    let best_block_header_result = rt.block_on(client.get_block_header(best_block_hash.to_string().as_str(), true));
    let (_, best_height) = best_block_header_result.unwrap();

    let mut resp = Vec::new();

    resp.write_u32::<BigEndian>(best_height - height + 1).unwrap();

    storage.insert(input.clone(), resp.clone().into());

    Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, resp.into()))
}

pub fn btc_tx_by_tx_id_run_rpc(input: &Bytes, client: &BitcoinRpcClient, gas_limit: u64, storage: &mut HashMap<Bytes, Bytes>) -> PrecompileResult {
    const BTC_TX_BY_TX_ID_BASE: u64 = 25_000;
    // 4 Bytes bit flag, 32 bytes txid
    if input.is_empty() || input.len() != 36 {
        return Ok(PrecompileOutput::new(BTC_TX_BY_TX_ID_BASE, vec![].into()));
    }

    if BTC_TX_BY_TX_ID_BASE > gas_limit {
        return Err(Error::OutOfGas.into());
    }

    let tx_id = &input[0..32];

    let bitflag1 = input[32];
    let include_tx_hash = (bitflag1 & (0x01 << 7)) != 0;
    let include_containing_block = (bitflag1 & (0x01 << 6)) != 0;
    let include_version = (bitflag1 & (0x01 << 5)) != 0;
    let include_sizes = (bitflag1 & (0x01 << 4)) != 0; // Size, vsize, weight
    let include_lock_time = (bitflag1 & (0x01 << 3)) != 0;
    let include_inputs = (bitflag1 & (0x01 << 2)) != 0;
    let include_input_source = (bitflag1 & (0x01 << 1)) != 0;
    let include_input_script_sig = (bitflag1 & 0x01) != 0;

    let bitflag2 = input[33];
    let include_input_seq = (bitflag2 & (0x01 << 7)) != 0;
    let include_outputs = (bitflag2 & (0x01 << 6)) != 0;
    let include_output_script = (bitflag2 & (0x01 << 5)) != 0;
    let include_output_address = (bitflag2 & (0x01 << 4)) != 0;
    let include_unspendable_outputs = (bitflag2 & (0x01 << 3)) != 0;
    let include_output_spent = (bitflag2 & (0x01 << 2)) != 0;
    let include_output_spent_by = (bitflag2 & (0x01 << 1)) != 0;

    let bitflag3 = input[34]; // Gives size limits for data which could get unexpectedly expensive to return

    // Two free bits here
    let max_inputs_exponent = (bitflag3 & (0x07 << 3)) >> 3; // bits xxXXXxxx used as 2^(X), b00=2^0=1, b01=2^1=2, ... up to 2^6=64 inputs
    let max_outputs_exponent = bitflag3 & 0x07; // bits xxxxxXXX used as 2^(X), b00=2^0=1, b01=2^1=2, ... up to 2^6=64 outputs

    let max_inputs: usize = 0x01 << max_inputs_exponent;
    let max_outputs: usize = 0x01 << max_outputs_exponent;

    let bitflag4 = input[35];

    // Four free bits here
    let max_input_script_sig_size_exponent = (bitflag4 & (0x03 << 2)) >> 2; // bits xxxxXXxx used as 2^(4+X)
    let max_output_script_size_exponent = bitflag4 & 0x03; // bits xxxxxxXX used as 2^(4+X)

    let max_input_script_sig_size = 0x01 << (4 + max_input_script_sig_size_exponent);
    let max_output_script_size = 0x01 << (4 + max_output_script_size_exponent);

    let rt = Runtime::new().unwrap();

    let tx_id_str = hex::encode(tx_id);
    let raw_transaction_result = rt.block_on(
        client.get_raw_transaction(&tx_id_str, None)
    );

    if raw_transaction_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_TX_BY_TX_ID_BASE, vec![].into()));
    }

    let (tx, block_hash) = raw_transaction_result.unwrap();

    let mut output: Vec<u8> = vec![];

    if include_containing_block {
        let binding: &[u8] = block_hash.as_ref();
        output.extend(binding.iter().rev().copied().collect::<Vec<u8>>().as_slice());
    }

    if include_version {
        output.write_u32::<BigEndian>(tx.version.0 as u32).unwrap();
    }

    if include_sizes {
        output.write_u32::<BigEndian>(tx.total_size() as u32).unwrap();
        output.write_u32::<BigEndian>(tx.base_size() as u32).unwrap();
    }

    if include_lock_time {
        output.write_u32::<BigEndian>(tx.lock_time.to_consensus_u32()).unwrap();
    }

    if include_inputs {
        let tx_input = tx.input;
        output.write_u16::<BigEndian>(tx_input.len() as u16).unwrap();

        for (index, tx_in ) in tx_input.iter().enumerate(){
            if index >= max_inputs {
                break;
            }

            let prev_in = tx_in.previous_output;

            // Handle coinbase transaction
            if !prev_in.is_null() {
                let tx_hash = prev_in.txid;
                let source_tx_result = rt.block_on(client.get_raw_transaction(tx_hash.to_string().as_str(), None));

                if source_tx_result.is_err() {
                    return Ok(PrecompileOutput::new(BTC_TX_BY_TX_ID_BASE, vec![].into()));
                }

                let (source_tx, _) = source_tx_result.unwrap();
                let value = source_tx.output[prev_in.vout as usize].value;

                output.write_u64::<BigEndian>(value.to_btc() as u64).unwrap();

                if include_input_source {
                    let prev_in_hash: &[u8] = prev_in.txid.as_ref();
                    output.extend_from_slice(prev_in_hash.iter().rev().copied().collect::<Vec<u8>>().as_slice());
                    output.write_u16::<BigEndian>(prev_in.vout as u16).unwrap()
                }

                if include_input_script_sig {
                    let script_sig = tx_in.script_sig.clone();
                    let mut chopped_input_script: Vec<u8> = vec![];
                    chopped_input_script.extend(script_sig.as_bytes());
                    if chopped_input_script.len() > max_input_script_sig_size {
                        chopped_input_script  = chopped_input_script[..max_input_script_sig_size].to_vec();
                    }

                    output.write_u16::<BigEndian>(tx_in.script_sig.len() as u16).unwrap();
                    output.extend(chopped_input_script);
                }
            } else {
                output.write_u64::<BigEndian>(0u64).unwrap();
                if include_input_source{
                    output.extend_from_slice(&[0; 32]);
                    output.write_u16::<BigEndian>(0u16).unwrap()
                }

                if include_input_script_sig {
                    output.write_u16::<BigEndian>(0).unwrap();
                }
            }

            if include_input_seq {
                let sequence = tx_in.sequence.to_consensus_u32();
                output.write_u32::<BigEndian>(sequence).unwrap()
            }
        }

    }

    if include_outputs {
        let mut unspendable = 0;
        for out in &tx.output {
            if out.script_pubkey.is_op_return() {
                unspendable += 1;
            }
        }

        let mut out_len = tx.output.len();
        if !include_unspendable_outputs{
            out_len -= unspendable;
        }

        output.write_u16::<BigEndian>(out_len as u16).unwrap();

        let count = 0;

        for (_, out) in tx.output.iter().enumerate(){
            if count >= max_outputs {
                break;
            }
            let is_unspendable = out.script_pubkey.is_op_return();
            if is_unspendable && !include_output_script {
                continue;
            }
            output.write_u64::<BigEndian>(out.value.to_btc() as u64).unwrap();
            if include_output_script {
                let script_pubkey = out.script_pubkey.clone();
                let mut chopped_out_script: Vec<u8> = vec![];
                chopped_out_script.extend(script_pubkey.as_bytes());
                if chopped_out_script.len() > max_output_script_size {
                    chopped_out_script  = chopped_out_script[..max_output_script_size].to_vec();
                }

                output.write_u16::<BigEndian>(out.script_pubkey.len() as u16).unwrap();
                output.extend(chopped_out_script);
            }
        }
    }

    Ok(PrecompileOutput::new(BTC_TX_BY_TX_ID_BASE, output.into()))
}

pub fn btc_tx_confirmations_run(input: &Bytes, gas_limit: u64, storage: &HashMap<Bytes, Bytes>) -> PrecompileResult {
    const BTC_TX_CONFIRMATIONS_BASE: u64 = 5_000;
    if input.is_empty() || input.len() != 32 {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    if BTC_TX_CONFIRMATIONS_BASE > gas_limit {
        return Err(Error::OutOfGas.into());
    }

    if let Some(cached_value) = storage.get(input) {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, cached_value.clone().into()));
    }

    Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()))
}

pub fn btc_header_n_run(input: &Bytes, gas_limit: u64, storage: &HashMap<Bytes, Bytes>) -> PrecompileResult {
    const BTC_HEADER_N_BASE: u64 = 6_000;
    if input.is_empty() || input.len() != 4 {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()));
    }

    if BTC_HEADER_N_BASE > gas_limit {
        return Err(Error::OutOfGas.into());
    }

    if let Some(cached_value) = storage.get(input) {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, cached_value.clone().into()));
    }

    Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()))
}

#[cfg(test)]
mod test {
    use core::fmt;
    use bitcoin::Script;
    use revm_primitives::{Bytes, hex::FromHex};

    use crate::btc_utilities::BitcoinRpcClient;
    use crate::HashMap;
    use crate::btc::{btc_header_n_run, btc_header_n_run_rpc, btc_tx_by_tx_id_run_rpc, btc_tx_confirmations_run, btc_tx_confirmations_run_rpc};

    const RPC_URL: &str = "https://bitcoin-testnet.public.blastapi.io";

    fn to_hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    struct BitcoinHeader {
        height: u32,
        block_hash: [u8; 32],
        version: u32,
        previous_block_hash: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: u32,
        nonce: u32,
    }

    impl fmt::Debug for BitcoinHeader {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "BitcoinHeader {{
    height: {},
    block_hash: {},
    version: {},
    previous_block_hash: {},
    merkle_root: {},
    timestamp: {},
    bits: {},
    nonce: {},
}}",
                self.height,
                to_hex_string(&self.block_hash),
                self.version,
                to_hex_string(&self.previous_block_hash),
                to_hex_string(&self.merkle_root),
                self.timestamp,
                self.bits,
                self.nonce,
            )
        }
    }

    fn to_u32(slice: &[u8]) -> u32 {
        u32::from_be_bytes(slice.try_into().unwrap())
    }

    fn to_bytes32(slice: &[u8]) -> [u8; 32] {
        slice.try_into().unwrap()
    }

    // Same logic as in Hemi's Bitcoin Toolkit contract
    fn parse_header(data: &[u8]) -> BitcoinHeader {
        let mut offset = 0;

        let height = to_u32(&data[offset..offset + 4]);
        offset += 4;

        let block_hash = to_bytes32(&data[offset..offset + 32]);
        offset += 32;

        let version = to_u32(&data[offset..offset + 4]);
        offset += 4;

        let previous_block_hash = to_bytes32(&data[offset..offset + 32]);
        offset += 32;

        let merkle_root = to_bytes32(&data[offset..offset + 32]);
        offset += 32;

        let timestamp = to_u32(&data[offset..offset + 4]);
        offset += 4;

        let bits = to_u32(&data[offset..offset + 4]);
        offset += 4;

        let nonce = to_u32(&data[offset..offset + 4]);
        offset += 4;

        BitcoinHeader {
            height,
            block_hash,
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        }
    }

    /// Sets bitflags for the first configuration
    pub fn set_flags1(
        include_block: bool,
        include_version: bool,
        include_size: bool,
        include_lock_time: bool,
        include_inputs: bool,
        include_source: bool,
        include_script_sig: bool,
    ) -> u8 {
        let mut flags = 0;
        if include_block {
            flags |= 1 << 6;
        }
        if include_version {
            flags |= 1 << 5;
        }
        if include_size {
            flags |= 1 << 4;
        }
        if include_lock_time {
            flags |= 1 << 3;
        }
        if include_inputs {
            flags |= 1 << 2;
        }
        if include_source {
            flags |= 1 << 1;
        }
        if include_script_sig {
            flags |= 1 << 0;
        }
        flags
    }

    /// Sets bitflags for the second configuration
    pub fn set_flags2(
        include_seq: bool,
        include_outputs: bool,
        include_output_script: bool,
        include_output_address: bool,
        include_op_return: bool,
        include_spent_status: bool,
        include_spent_by: bool,
    ) -> u8 {
        let mut flags = 0;
        if include_seq {
            flags |= 1 << 7;
        }
        if include_outputs {
            flags |= 1 << 6;
        }
        if include_output_script {
            flags |= 1 << 5;
        }
        if include_output_address {
            flags |= 1 << 4;
        }
        if include_op_return {
            flags |= 1 << 3;
        }
        if include_spent_status {
            flags |= 1 << 2;
        }
        if include_spent_by {
            flags |= 1 << 1;
        }
        flags
    }

    /// Sets bitflag3 for maximum inputs and outputs exponent
    pub fn set_flag3(max_inputs_exponent: u8, max_outputs_exponent: u8) -> u8 {
        (max_inputs_exponent << 3) | max_outputs_exponent
    }

    /// Sets bitflag4 for maximum script sizes exponent
    pub fn set_flag4(max_input_script_sig_size_exponent: u8, max_output_script_size_exponent: u8) -> u8 {
        (max_input_script_sig_size_exponent << 2) | max_output_script_size_exponent
    }

    pub struct ParsedTransaction {
        containing_block_hash: [u8; 32],
        transaction_version: u32,
        size: u32,
        v_size: u32,
        lock_time: u32,
        inputs: Vec<ParsedTxInput>,
        outputs: Vec<ParsedTxOutput>,
        total_inputs: u16,
        total_outputs: u16,
        contains_all_inputs: bool,
        contains_all_outputs: bool,
    }

    impl fmt::Debug for ParsedTransaction {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ParsedTransaction")
                .field(
                    "containing_block_hash",
                    &format_args!("{:?}", hex::encode(self.containing_block_hash)),
                )
                .field("transaction_version", &self.transaction_version)
                .field("size", &self.size)
                .field("v_size", &self.v_size)
                .field("lock_time", &self.lock_time)
                .field("inputs", &self.inputs)
                .field("outputs", &self.outputs)
                .field("total_inputs", &self.total_inputs)
                .field("total_outputs", &self.total_outputs)
                .field("contains_all_inputs", &self.contains_all_inputs)
                .field("contains_all_outputs", &self.contains_all_outputs)
                .finish()
        }
    }


    pub struct ParsedTxInput {
        in_value: u64,
        input_tx_id: [u8; 32],
        source_index: u16,
        script_buf: Vec<u8>,
        sequence: u32,
    }

    pub struct ParsedTxOutput {
        out_value: u64,
        script: Vec<u8>,
    }

    impl fmt::Debug for ParsedTxInput {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let script = Script::from_bytes(&self.script_buf);
            f.debug_struct("ParsedTxInput")
                .field("in_value", &self.in_value)
                .field(
                    "input_tx_id",
                    &format_args!("{:?}", hex::encode(self.input_tx_id)),
                )
                .field("source_index", &self.source_index)
                .field(
                    "script_buf",
                    &script.to_asm_string(),
                )
                .field("sequence", &self.sequence)
                .finish()
        }
    }

    impl fmt::Debug for ParsedTxOutput {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let script = Script::from_bytes(&self.script);
            f.debug_struct("ParsedTxOutput")
                .field("out_value", &self.out_value)
                .field(
                    "script",
                    &script.to_asm_string(),
                )
                .finish()
        }
    }

    pub fn parse_bytes_to_transaction(data: &[u8]) -> ParsedTransaction {
        let mut offset = 0;
        let containing_block_hash = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
        let transaction_version = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let size = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let v_size = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let lock_time = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let (inputs, new_offset, total_inputs) = parse_transaction_inputs(data, offset);
        offset = new_offset;

        let (outputs, new_offset, total_outputs) = parse_transaction_outputs(data, offset);
        offset = new_offset;

        let contains_all_inputs = total_inputs as usize == inputs.len();
        let contains_all_outputs = total_outputs as usize == outputs.len();

        ParsedTransaction {
            containing_block_hash,
            transaction_version,
            size,
            v_size,
            lock_time,
            inputs,
            outputs,
            total_inputs,
            total_outputs,
            contains_all_inputs,
            contains_all_outputs,
        }
    }

    pub fn parse_transaction_inputs(data: &[u8], mut offset: usize) -> (Vec<ParsedTxInput>, usize, u16) {
        let total_inputs = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let mut inputs = Vec::with_capacity(total_inputs as usize);
        for _ in 0..total_inputs {
            let in_value = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;

            let input_tx_id = data[offset..offset + 32].try_into().unwrap();
            offset += 32;

            let source_index = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let script_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let script_buf = &data[offset..offset + script_len as usize];
            offset += script_len as usize;

            let sequence = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;

            inputs.push(ParsedTxInput {
                in_value,
                input_tx_id,
                source_index,
                script_buf: script_buf.to_vec(),
                sequence,
            });
        }

        (inputs, offset, total_inputs)
    }

    pub fn parse_transaction_outputs(data: &[u8], mut offset: usize) -> (Vec<ParsedTxOutput>, usize, u16) {
        let total_outputs = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let mut outputs = Vec::with_capacity(total_outputs as usize);
        for _ in 0..total_outputs {
            let out_value = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;

            let out_script_pubkey_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            let script = data[offset..offset + out_script_pubkey_len].to_vec();
            offset += out_script_pubkey_len;

            outputs.push(ParsedTxOutput { out_value, script });
        }

        (outputs, offset, total_outputs)
    }

    #[test]
    fn test_header_n() {
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );
        let height = 2873745u32.to_be_bytes();
        let input = Bytes::from(height);
        let target_gas: u64 = 30_000_000;
        let mut storage: HashMap<Bytes, Bytes> = HashMap::new();
        let res = btc_header_n_run_rpc(&input, &client, target_gas, &mut storage);
        let parsed_header = parse_header(res.clone().unwrap().bytes.as_ref());
        let expected_output = Bytes::from_hex("0x002bd99100000000000002b2622295c76df6ae5f6e9c02d64a914cb9736980d01750e1052000000000000000000007a0e5c4e177ab17da3beaea6aba969f08e71f830ee00d3c566d73b1db61d8ec6e707e2013e762ac6e60232a72bcef483f866acae87c186bfd8a66bea8641d00ffffcebb0dee").unwrap();
        assert_eq!(expected_output, res.clone().unwrap().bytes);
        let cached_res = btc_header_n_run(&input, target_gas, &storage);
        assert_eq!(res, cached_res);
    }

    #[test]
    fn test_tx_confirmation() {
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );
        let tx_id = hex::decode("ae8601bd8ca8a23e7261cb81b4ed4f221c906bf59808d1a77eda57eb6d65605d").unwrap();
        let input = Bytes::from(tx_id);
        let target_gas: u64 = 30_000_000;
        let mut storage: HashMap<Bytes, Bytes> = HashMap::new();
        let res = btc_tx_confirmations_run_rpc(&input, &client, target_gas, &mut storage);
        let cached_res = btc_tx_confirmations_run(&input, target_gas, &storage);
        assert_eq!(res, cached_res);
    }

    #[test]
    fn test_tx_by_tx_id() {
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );
        let mut input = hex::decode("ae8601bd8ca8a23e7261cb81b4ed4f221c906bf59808d1a77eda57eb6d65605d").unwrap();
        let bit_flag1 = set_flags1(true, true, true, true, true, true, true);
        let bit_flag2 = set_flags2(true, true, true, true, true, true, true);
        let bit_flag3 = set_flag3(5, 5);
        let bit_flag4 = set_flag4(2, 2);
        input.extend(vec![bit_flag1, bit_flag2, bit_flag3, bit_flag4]);
        let input_encoded = Bytes::from(input);
        let target_gas: u64 = 30_000_000;
        let mut storage: HashMap<Bytes, Bytes> = HashMap::new();
        let res = btc_tx_by_tx_id_run_rpc(&input_encoded, &client, target_gas, &mut storage);
        let expected_output = Bytes::from_hex("0x0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf00000002000000a5000000810000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff000200000000000000020016001423cf56400dd825d0d998a9c313d6bc6a848014e6000000000000000000266a24aa21a9edd862616e2b962d2e772c910b8103d2b0fcfa73182b2ca8fc65b2dd559bc8e7bf").unwrap();
        assert_eq!(res.unwrap().bytes, expected_output);
    }
}
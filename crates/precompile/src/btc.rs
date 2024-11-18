use byteorder::{BigEndian, WriteBytesExt};
use tokio::runtime::Runtime;

use revm_primitives::{PrecompileOutput, PrecompileResult};

use crate::{Bytes, Error, HashMap};
use crate::btc_utilities::BitcoinRpcClient;
use crate::primitives::hex;

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

    let rt = Runtime::new().unwrap();

    let block_header_result = rt.block_on(client.get_block_header(block_hash.as_str(), true));

    if block_header_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_HEADER_N_BASE, vec![].into()));
    }

    let block_header = block_header_result.unwrap();

    let mut resp = Vec::new();

    resp.write_u32::<BigEndian>(block_header.height.unwrap()).unwrap();

    let block_hash_bytes = hex::decode(block_header.hash).unwrap();
    resp.extend_from_slice(&block_hash_bytes);

    resp.write_u32::<BigEndian>(block_header.version.unwrap()).unwrap();

    let prev_hash_bytes = hex::decode(block_header.previousblockhash.unwrap()).unwrap();
    resp.extend_from_slice(&prev_hash_bytes);

    let merkle_root_bytes = hex::decode(block_header.merkleroot.unwrap()).unwrap();
    resp.extend_from_slice(&merkle_root_bytes);
    resp.write_u32::<BigEndian>(block_header.time.unwrap() as u32).unwrap();

    let bits = u32::from_str_radix(block_header.bits.unwrap().as_str(), 16).unwrap();
    resp.write_u32::<BigEndian>(bits).unwrap();
    resp.write_u32::<BigEndian>(block_header.nonce.unwrap()).unwrap();

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
        client.get_raw_transaction(&tx_id_str, 1, None)
    );
    if raw_transaction_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    let tx = raw_transaction_result.unwrap();

    let rt = Runtime::new().unwrap();

    let block_header_result = rt.block_on(client.get_block_header(tx.blockhash.unwrap().as_str(), true));

    if block_header_result.is_err() {
        return Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, vec![].into()));
    }

    let block_header = block_header_result.unwrap();

    let mut resp = Vec::new();

    resp.write_u32::<BigEndian>(block_header.height.unwrap()).unwrap();

    storage.insert(input.clone(), resp.clone().into());

    Ok(PrecompileOutput::new(BTC_TX_CONFIRMATIONS_BASE, resp.into()))
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
    use revm_primitives::{Bytes, hex::FromHex};

    use crate::btc_utilities::BitcoinRpcClient;
    use crate::HashMap;
    use crate::btc::{btc_header_n_run, btc_header_n_run_rpc, btc_tx_confirmations_run, btc_tx_confirmations_run_rpc};

    const RPC_URL: &str = "https://bitcoin-testnet.public.blastapi.io";

    #[test]
    fn test_header_n() {
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );
        let height = 3436118u32.to_be_bytes();
        let input = Bytes::from(height);
        let target_gas: u64 = 30_000_000;
        let mut storage: HashMap<Bytes, Bytes> = HashMap::new();
        let res = btc_header_n_run_rpc(&input, &client, target_gas, &mut storage);
        let expected_output = Bytes::from_hex("0x00346e560000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf295d0000000000000c94fdda2fe93a93151ba76a17668a32c33a51604952a8a9571c6ce1a00adc03d712ef49008a2764587974c705c9562b259d1a75b37885483c22fe4067374953190ffff04655c4b6").unwrap();
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
        let expected_output = Bytes::from_hex("0x00346e56").unwrap();
        assert_eq!(expected_output, res.clone().unwrap().bytes);
        let cached_res = btc_tx_confirmations_run(&input, target_gas, &storage);
        assert_eq!(res, cached_res);
    }
}
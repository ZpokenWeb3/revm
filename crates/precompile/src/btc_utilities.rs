use core::error::Error;

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct BitcoinRpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    id: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Vec<serde_json::Value>,
    id: u64,
}

// `getblock` response struct
#[derive(Debug, Deserialize)]
struct Block {
    hash: BlockHash,
    confirmations: Option<i64>,
    size: Option<u32>,
    strippedsize: Option<u32>,
    weight: Option<u32>,
    height: Option<u32>,
    version: Option<u32>,
    versionHex: Option<String>,
    merkleroot: Option<String>,
    tx: Option<Vec<String>>,
    time: Option<u64>,
    mediantime: Option<u64>,
    nonce: Option<u32>,
    bits: Option<String>,
    difficulty: Option<f64>,
    chainwork: Option<String>,
    nTx: Option<u32>,
    previousblockhash: Option<String>,
    nextblockhash: Option<String>,
}

// Exclude confirmations
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.size == other.size
            && self.strippedsize == other.strippedsize
            && self.weight == other.weight
            && self.height == other.height
            && self.version == other.version
            && self.versionHex == other.versionHex
            && self.merkleroot == other.merkleroot
            && self.tx == other.tx
            && self.time == other.time
            && self.mediantime == other.mediantime
            && self.nonce == other.nonce
            && self.bits == other.bits
            && self.difficulty == other.difficulty
            && self.chainwork == other.chainwork
            && self.nTx == other.nTx
            && self.previousblockhash == other.previousblockhash
            && self.nextblockhash == other.nextblockhash
    }
}

// `getblockhash` response type
type BlockHash = String;

// `getblockheader` response struct
#[derive(Debug, Deserialize)]
pub struct BlockHeader {
    pub hash: BlockHash,
    pub confirmations: Option<i64>,
    pub height: Option<u32>,
    pub version: Option<u32>,
    pub versionHex: Option<String>,
    pub merkleroot: Option<String>,
    pub time: Option<u64>,
    pub mediantime: Option<u64>,
    pub nonce: Option<u32>,
    pub bits: Option<String>,
    pub difficulty: Option<f64>,
    pub chainwork: Option<String>,
    pub nTx: Option<u32>,
    pub previousblockhash: Option<String>,
    pub nextblockhash: Option<String>,
}

// Exclude confirmations
impl PartialEq for BlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.height == other.height
            && self.version == other.version
            && self.versionHex == other.versionHex
            && self.merkleroot == other.merkleroot
            && self.time == other.time
            && self.mediantime == other.mediantime
            && self.nonce == other.nonce
            && self.bits == other.bits
            && self.difficulty == other.difficulty
            && self.chainwork == other.chainwork
            && self.nTx == other.nTx
            && self.previousblockhash == other.previousblockhash
            && self.nextblockhash == other.nextblockhash
    }
}

#[derive(Deserialize, Debug)]
pub struct VerboseTransaction {
    pub txid: String,
    pub hash: Option<String>,
    pub size: Option<u32>,
    pub vsize: Option<u32>,
    pub weight: Option<u32>,
    pub version: Option<u32>,
    pub locktime: Option<u32>,
    pub vin: Option<Vec<TransactionInput>>,
    pub vout: Option<Vec<TransactionOutput>>,
    pub blockhash: Option<BlockHash>,
    pub confirmations: Option<u32>,
    pub blocktime: Option<u64>,
    pub time: Option<u64>,
}

impl PartialEq for VerboseTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.txid == other.txid
            && self.hash == other.hash
            && self.size == other.size
            && self.vsize == other.vsize
            && self.weight == other.weight
            && self.version == other.version
            && self.locktime == other.locktime
            && self.vin == other.vin
            && self.vout == other.vout
            && self.blockhash == other.blockhash
            && self.blocktime == other.blocktime
            && self.time == other.time
    }
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct TransactionInput {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    pub scriptSig: Option<ScriptSig>,
    pub sequence: Option<u64>,
    pub txinwitness: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct TransactionOutput {
    pub value: f64,
    pub n: u32,
    pub scriptPubKey: ScriptPubKey,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct ScriptPubKey {
    pub asm: String,
    pub hex: String,
    pub type_field: Option<String>,
    pub address: Option<String>,
}

pub struct BitcoinRpcClient {
    client: Client,
    url: String,
}

impl BitcoinRpcClient {
    pub fn new(url: String) -> Self {
        Self {
            client: Client::new(),
            url,
        }
    }

    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, Box<dyn Error>> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await?;

        let rpc_response: BitcoinRpcResponse<T> = response.json().await?;

        if let Some(error) = rpc_response.error {
            Err(format!("RPC Error {}: {}", error.code, error.message).into())
        } else {
            rpc_response
                .result
                .ok_or_else(|| "Missing result in response".into())
        }
    }

    pub async fn get_block(&self, blockhash: &str, verbosity: u8) -> Result<Block, Box<dyn Error>> {
        self.rpc_call("getblock", vec![blockhash.into(), verbosity.into()])
            .await
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Box<dyn Error>> {
        self.rpc_call("getblockhash", vec![height.into()]).await
    }

    pub async fn get_block_header(
        &self,
        blockhash: &str,
        verbose: bool,
    ) -> Result<BlockHeader, Box<dyn Error>> {
        self.rpc_call("getblockheader", vec![blockhash.into(), verbose.into()])
            .await
    }

    pub async fn get_raw_transaction(
        &self,
        txid: &str,
        verbose: u8,
        blockhash: Option<&str>,
    ) -> Result<VerboseTransaction, Box<dyn Error>> {
        let mut params = vec![txid.into(), verbose.into()];
        if let Some(blockhash) = blockhash {
            params.push(blockhash.into());
        }

        self.rpc_call("getrawtransaction", params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RPC_URL: &str = "https://bitcoin-testnet.public.blastapi.io";

    #[tokio::test]
    async fn test_get_block_hash() {
        let block_height = 3436118;
        let expected_hash = "0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let block_hash = client.get_block_hash(block_height).await.unwrap();
        assert_eq!(block_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_get_block_header() {
        let expected_block_header = BlockHeader{
            hash: "0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf".to_string(),
            confirmations: Some(82),
            height: Some(3436118),
            version: Some(693960704),
            versionHex: Some("295d0000".to_string()),
            merkleroot: Some("a00adc03d712ef49008a2764587974c705c9562b259d1a75b37885483c22fe40".to_string()),
            time: Some(1731676499),
            mediantime: Some(1731676499),
            nonce: Some(1180026038),
            bits: Some("190ffff0".to_string()),
            difficulty: Some(268435456f64),
            chainwork: Some("000000000000000000000000000000000000000000001052dd48d75e047122c3".to_string()),
            nTx: Some(3529),
            previousblockhash: Some("000000000c94fdda2fe93a93151ba76a17668a32c33a51604952a8a9571c6ce1".to_string()),
            nextblockhash: Some("000000000c2b65f222587faa6253cb6b61db548e1d09aef3d93651d6a3ddb9fd".to_string()),
        };
        let hash = "0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let block_header = client.get_block_header(hash, true).await.unwrap();
        assert_eq!(expected_block_header, block_header);
    }

    #[tokio::test]
    async fn test_get_block() {
        let expected_block = Block{
            hash: "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2".to_string(),
            confirmations: Some(3236203),
            size: Some(189),
            strippedsize: Some(189),
            weight: Some(756),
            height: Some(200000),
            version: Some(2),
            versionHex: Some("00000002".to_string()),
            merkleroot: Some("1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617".to_string()),
            tx: Some(vec!["1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617".to_string()]),
            time: Some(1393659510),
            mediantime: Some(1393659424),
            nonce: Some(2304738937),
            bits: Some("1c0180ab".to_string()),
            difficulty: Some(170.3677075399848),
            chainwork: Some("00000000000000000000000000000000000000000000000004504fe4ad3e1db2".to_string()),
            nTx: Some(1),
            previousblockhash: Some("0000000000c470c4a573272aa4a680c93fc4c2f5df8ce9546441796f73277334".to_string()),
            nextblockhash: Some("00000000006a196b74cab788d638eefd983fe0bddea94b4839499be94d654e37".to_string()),
        };
        let hash = "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let block = client.get_block(hash, 1).await.unwrap();
        assert_eq!(expected_block, block);
    }

    #[tokio::test]
    async fn test_get_raw_transaction() {
        let expected_script_pub_key = ScriptPubKey{
            asm: "02802e2df5f9fb88065630e5fa3b6f7b7a89deef2b6a3cb5203cd0b897f66acae4 OP_CHECKSIG".to_string(),
            hex: "2102802e2df5f9fb88065630e5fa3b6f7b7a89deef2b6a3cb5203cd0b897f66acae4ac".to_string(),
            type_field: None,
            address: None,
        };
        let expected_tx_input = TransactionInput{
            txid: None,
            vout: None,
            scriptSig: None,
            sequence: Some(4294967295),
            txinwitness: None,
        };
        let expected_tx_output = TransactionOutput{
            value: 50.0,
            n: 0,
            scriptPubKey: expected_script_pub_key,
        };
        let expected_transaction = VerboseTransaction{
            txid: "1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617".to_string(),
            hash: Some("1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617".to_string()),
            size: Some(108),
            vsize: Some(108),
            weight: Some(432),
            version: Some(1),
            locktime: Some(0),
            vin: Some(vec![expected_tx_input]),
            vout: Some(vec![expected_tx_output]),
            blockhash: Some("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2".to_string()),
            confirmations: Some(3242466),
            blocktime: Some(1393659510),
            time: Some(1393659510),
        };
        let tx_id = "1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let raw_transaction = client.get_raw_transaction(tx_id, 1, None).await.unwrap();
        assert_eq!(expected_transaction, raw_transaction);
    }
}
use std::error::Error;
use core::str::FromStr;
use bitcoin::block::{Header, Version};
use bitcoin::{Amount, Block, BlockHash, CompactTarget, Denomination, OutPoint, ScriptBuf, Sequence, Transaction, Txid, TxIn, TxMerkleNode, TxOut, Witness};
use bitcoin::absolute::LockTime;

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: f64, // Value in BTC
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    pub script_pub_key: ScriptPubKey,
}


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
struct BlockRepr {
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
impl PartialEq for BlockRepr {
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

// `getblockheader` response struct
#[derive(Debug, Deserialize)]
pub struct HeaderRepr {
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
impl PartialEq for HeaderRepr {
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



#[derive(Deserialize, Debug, PartialEq, Clone)]
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

    pub async fn get_block(&self, blockhash: &str) -> Result<Block, Box<dyn Error>> {
        let block_repr = self.rpc_call::<BlockRepr>("getblock", vec![blockhash.into(), 1.into()])
            .await?;
        let mut transactions: Vec<Transaction> = vec![];
        if let Some(txs) = block_repr.tx {
            for tx_str in txs{
                let (tx, _) = self.get_raw_transaction(tx_str.as_str(), Some(blockhash)).await?;
                transactions.push(tx);
            }
        }

        let bits_str = block_repr.bits.as_ref().unwrap();
        let bits_hex = format!("0x{}", bits_str);

        let header = Header {
            version: Version::from_consensus(block_repr.version.unwrap() as i32),
            prev_blockhash: BlockHash::from_str(block_repr.previousblockhash.unwrap().as_str()).unwrap(),
            merkle_root: TxMerkleNode::from_str(block_repr.merkleroot.unwrap().as_str()).unwrap(),
            time: block_repr.time.unwrap() as u32,
            bits: CompactTarget::from_hex(bits_hex.as_str()).unwrap(),
            nonce: block_repr.nonce.unwrap(),
        };

        Ok(Block{
            header,
            txdata: transactions,
        })
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Box<dyn Error>> {
        self.rpc_call("getblockhash", vec![height.into()]).await
    }

    pub async fn get_best_block_hash(&self) -> Result<BlockHash, Box<dyn Error>> {
        self.rpc_call("getbestblockhash", vec![]).await
    }

    pub async fn get_block_header(
        &self,
        blockhash: &str,
        verbose: bool,
    ) -> Result<(Header, u32), Box<dyn Error>> {
        let block_header_repr = self.rpc_call::<HeaderRepr>("getblockheader", vec![blockhash.into(), verbose.into()])
            .await?;
        let bits_str = block_header_repr.bits.as_ref().unwrap();
        let bits_hex = format!("0x{}", bits_str);
        Ok((Header {
            version: Version::from_consensus(block_header_repr.version.unwrap() as i32),
            prev_blockhash: BlockHash::from_str(block_header_repr.previousblockhash.unwrap().as_str()).unwrap(),
            merkle_root: TxMerkleNode::from_str(block_header_repr.merkleroot.unwrap().as_str()).unwrap(),
            time: block_header_repr.time.unwrap() as u32,
            bits: CompactTarget::from_hex(bits_hex.as_str()).unwrap(),
            nonce: block_header_repr.nonce.unwrap(),
        }, block_header_repr.height.unwrap()))
    }

    pub async fn get_raw_transaction(
        &self,
        txid: &str,
        blockhash: Option<&str>,
    ) -> Result<(Transaction, BlockHash), Box<dyn Error>> {
        let mut params = vec![txid.into(), 1.into()];
        if let Some(blockhash) = blockhash {
            params.push(blockhash.into());
        }

        let transaction = self.rpc_call::<VerboseTransaction>("getrawtransaction", params).await?;
        let version = transaction.version.unwrap() as i32;
        let tx_version = match version {
            1 => { bitcoin::blockdata::transaction::Version::ONE }
            2 => { bitcoin::blockdata::transaction::Version::TWO }
            _ => { bitcoin::blockdata::transaction::Version::non_standard(version) }
        };
        let mut input = vec![];

        if let Some(vin) = transaction.vin {
            for v_in in vin{
                let mut witness =  Witness::new();
                if let Some(w_in) = v_in.txinwitness {
                    for w_in_hex in w_in {
                        let hex_w = hex::decode(w_in_hex.as_str()).unwrap();
                        witness.push(hex_w);
                    }
                };

                let script_sig = if let Some(scriptSig) = v_in.scriptSig {
                    ScriptBuf::from_hex(scriptSig.hex.as_str()).unwrap()
                } else {
                    ScriptBuf::new()
                };

                let out_point = if let Some(txid) = v_in.txid {
                    OutPoint::new(Txid::from_str(txid.as_str()).unwrap(), v_in.vout.unwrap())
                } else {
                    // Coinbase transaction
                    OutPoint::null()
                };
                let tx_in = TxIn {
                    previous_output: out_point,
                    script_sig,
                    sequence: Sequence::from_consensus(v_in.sequence.unwrap() as u32),
                    witness,
                };
                input.push(tx_in);
            };
        }

        let mut output: Vec<TxOut> = vec![];

        if let Some(vout) = transaction.vout{
            for v_out in vout{
                let script_buf = ScriptBuf::from_hex(v_out.scriptPubKey.hex.as_str()).unwrap();
                let tx_out = TxOut{
                    value: Amount::from_float_in(v_out.value, Denomination::Bitcoin).unwrap(),
                    script_pubkey: script_buf,
                };
                output.push(tx_out);
            }
        }

        Ok((Transaction {
            version: tx_version,
            lock_time: LockTime::from_consensus(transaction.locktime.unwrap()),
            input,
            output,
        }, transaction.blockhash.unwrap()))
    }
    pub async fn get_utxos(&self, address: &str, page: usize, page_size: usize) -> Result<Vec<Utxo>, Box<dyn Error>> {
        let all_utxos: Vec<Utxo> = self
            .rpc_call(
                "listunspent",
                vec![0.into(), 9999999.into(), serde_json::to_value(vec![address]).unwrap()],
            )
            .await?;

        // Paginate the results
        let start = page * page_size;
        let end = std::cmp::min(start + page_size, all_utxos.len());
        if start >= all_utxos.len() {
            return Ok(vec![]); // No more UTXOs on this page
        }

        Ok(all_utxos[start..end].to_vec())
    }


    pub async fn get_balance_by_address(&self, address: &str) -> Result<u64, Box<dyn Error>> {
        let params = vec![serde_json::json!(address)];
        let balance = self.rpc_call::<u64>("getbalancebyaddress", params).await?;
        Ok(balance)
    }
    

}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use bitcoin::block::Header;
    use super::*;

    const RPC_URL: &str = "https://bitcoin-testnet.public.blastapi.io";

    #[tokio::test]
    async fn test_get_balance_by_address() {
        let client: BitcoinRpcClient = BitcoinRpcClient::new("https://bitcoin-testnet.public.blastapi.io".to_string());
        let address = "19MWZb6No9C4BP1UAwtTptV4EtwQNe3uud";
        let balance = client.get_balance_by_address(address).await;
    
        match balance {
            Ok(amount) => println!("Balance: {}", amount),
            Err(e) => panic!("Error fetching balance: {}", e),
        }
    }
    

    #[tokio::test]
    async fn test_get_block_hash() {
        let block_height = 3436118;
        let expected_hash = BlockHash::from_str("0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf").unwrap();
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );
        let block_hash = client.get_block_hash(block_height).await.unwrap();
        assert_eq!(block_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_get_block_header() {
        let expected_block_header = Header {
            version: Version::from_consensus(693960704),
            prev_blockhash: BlockHash::from_str("000000000c94fdda2fe93a93151ba76a17668a32c33a51604952a8a9571c6ce1").unwrap(),
            merkle_root: TxMerkleNode::from_str("a00adc03d712ef49008a2764587974c705c9562b259d1a75b37885483c22fe40").unwrap(),
            time: 1731676499,
            bits: CompactTarget::from_hex("0x190ffff0").unwrap(),
            nonce: 1180026038,
        };
        let expected_height = 3436118;
        let hash = "0000000000000007a70b3a5b094de30175a5a803e10c29ebf0133ad271293adf";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let (block_header, height) = client.get_block_header(hash, true).await.unwrap();
        assert_eq!(expected_block_header, block_header);
        assert_eq!(expected_height, height);
    }

    #[tokio::test]
    async fn test_get_block() {
        let expected_header = Header {
            version: Version::from_consensus(2),
            prev_blockhash: BlockHash::from_str("0000000000c470c4a573272aa4a680c93fc4c2f5df8ce9546441796f73277334").unwrap(),
            merkle_root: TxMerkleNode::from_str("1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617").unwrap(),
            time: 1393659510,
            bits: CompactTarget::from_hex("0x1c0180ab").unwrap(),
            nonce: 2304738937,
        };
        let expected_script_pubkey = ScriptBuf::from_hex("2102802e2df5f9fb88065630e5fa3b6f7b7a89deef2b6a3cb5203cd0b897f66acae4ac").unwrap();
        let expected_transaction = Transaction{
            version: bitcoin::blockdata::transaction::Version::ONE,
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn{
                previous_output: Default::default(),
                script_sig: Default::default(),
                sequence: Sequence::from_consensus(4294967295),
                witness: Default::default(),
            }],
            output: vec![TxOut{
                value: Amount::from_float_in(50.0, Denomination::Bitcoin).unwrap(),
                script_pubkey: expected_script_pubkey,
            }],
        };
        let expected_block = Block{
            header: expected_header,
            txdata: vec![expected_transaction],
        };
        let hash = "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let block = client.get_block(hash).await.unwrap();
        assert_eq!(expected_block, block);
    }

    #[tokio::test]
    async fn test_get_raw_transaction() {
        let expected_script_pubkey = ScriptBuf::from_hex("2102802e2df5f9fb88065630e5fa3b6f7b7a89deef2b6a3cb5203cd0b897f66acae4ac").unwrap();
        let expected_transaction = Transaction{
            version: bitcoin::blockdata::transaction::Version::ONE,
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn{
                previous_output: Default::default(),
                script_sig: Default::default(),
                sequence: Sequence::from_consensus(4294967295),
                witness: Default::default(),
            }],
            output: vec![TxOut{
                value: Amount::from_float_in(50.0, Denomination::Bitcoin).unwrap(),
                script_pubkey: expected_script_pubkey,
            }],
        };
        let tx_id = "1712247396a07e303a0ea33fe554754cc5acb1b182872dce7f8d2ddc36a23617";
        let client = BitcoinRpcClient::new(
            RPC_URL.to_string(),
        );

        let (raw_transaction, block_hash) = client.get_raw_transaction(tx_id,  None).await.unwrap();
        assert_eq!(expected_transaction, raw_transaction);
    }    

}

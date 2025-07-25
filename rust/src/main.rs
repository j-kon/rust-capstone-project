#![allow(unused)]
use bitcoin::hex::DisplayHex;
use bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;

// Node access params
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";

// Custom deserializers for RPC responses
#[derive(Deserialize, Debug)]
struct CreateWalletResult {
    name: String,
    warning: Option<String>,
}

#[derive(Deserialize, Debug)]
struct GenerateToAddressResult {
    address: String,
    blocks: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct SendResult {
    complete: bool,
    txid: String,
}

#[derive(Deserialize, Debug)]
struct MempoolEntry {
    txid: String,
    #[serde(rename = "wtxid")]
    wtxid: String,
    fees: MempoolFees,
}

#[derive(Deserialize, Debug)]
struct MempoolFees {
    base: f64,
    modified: f64,
    ancestor: f64,
    descendant: f64,
}

#[derive(Deserialize, Debug)]
struct TransactionDetail {
    txid: String,
    blockhash: String,
    blockheight: u64,
    decoded: DecodedTransaction,
    fee: f64,
}

#[derive(Deserialize, Debug)]
struct DecodedTransaction {
    txid: String,
    vin: Vec<TransactionInput>,
    vout: Vec<TransactionOutput>,
}

#[derive(Deserialize, Debug)]
struct TransactionInput {
    txid: Option<String>,
    vout: Option<u32>,
    #[serde(rename = "scriptSig")]
    script_sig: Option<ScriptSig>,
    sequence: Option<u32>,
    txinwitness: Option<Vec<String>>,
    prevout: Option<PrevOut>,
}

#[derive(Deserialize, Debug)]
struct ScriptSig {
    asm: String,
    hex: String,
}

#[derive(Deserialize, Debug)]
struct PrevOut {
    generated: Option<bool>,
    height: Option<u64>,
    value: f64,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Deserialize, Debug)]
struct TransactionOutput {
    value: f64,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Deserialize, Debug)]
struct ScriptPubKey {
    asm: String,
    hex: String,
    #[serde(rename = "type")]
    script_type: String,
    address: Option<String>,
}

fn main() -> bitcoincore_rpc::Result<()> {
    // Connect to Bitcoin Core RPC
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    println!("Connected to Bitcoin Core RPC");

    // Get blockchain info
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Current block height: {}", blockchain_info.blocks);

    // Step 1: Create/Load the wallets named 'Miner' and 'Trader'
    println!("\n=== Creating/Loading Wallets ===");
    
    // Create Miner wallet
    let miner_wallet = create_or_load_wallet(&rpc, "Miner")?;
    println!("Miner wallet ready: {}", miner_wallet.name);
    
    // Create Trader wallet  
    let trader_wallet = create_or_load_wallet(&rpc, "Trader")?;
    println!("Trader wallet ready: {}", trader_wallet.name);

    // Connect to Miner wallet specifically
    let miner_rpc = Client::new(
        &format!("{}/wallet/Miner", RPC_URL),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Connect to Trader wallet specifically
    let trader_rpc = Client::new(
        &format!("{}/wallet/Trader", RPC_URL),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Step 2: Generate mining address from Miner wallet
    println!("\n=== Generating Mining Address ===");
    let mining_address_unchecked = miner_rpc.get_new_address(Some("Mining Reward"), None)?;
    let mining_address = mining_address_unchecked.require_network(Network::Regtest)
        .expect("Failed to set regtest network on mining address");
    println!("Mining address generated: {}", mining_address);

    // Step 3: Mine blocks until Miner wallet has positive balance
    println!("\n=== Mining Blocks for Initial Balance ===");
    let mut blocks_mined = 0;
    let mut miner_balance = Amount::ZERO;
    
    // In Bitcoin regtest, coinbase rewards need 100 confirmations to be spendable
    // We need to mine at least 101 blocks to have spendable coins
    while miner_balance == Amount::ZERO {
        // Mine a block to the mining address
        let block_hashes = rpc.generate_to_address(1, &mining_address)?;
        blocks_mined += 1;
        
        // Check balance
        miner_balance = miner_rpc.get_balance(None, None)?;
        
        if blocks_mined % 10 == 0 {
            println!("Mined {} blocks, current balance: {} BTC", blocks_mined, miner_balance.to_btc());
        }
        
        // Safety check to avoid infinite loop
        if blocks_mined > 200 {
            println!("Mined {} blocks, breaking to avoid infinite loop", blocks_mined);
            break;
        }
    }
    
    println!("Mined {} blocks to achieve positive balance", blocks_mined);
    println!("Miner wallet balance: {} BTC", miner_balance.to_btc());
    
    // Comment about wallet balance behavior:
    // In Bitcoin, coinbase transaction outputs (block rewards) have a maturity period of 100 blocks
    // before they can be spent. This is a consensus rule that prevents issues if blocks are reorganized.
    // That's why we need to mine at least 101 blocks to have any spendable balance.

    // Step 4: Create receiving address in Trader wallet
    println!("\n=== Creating Trader Receiving Address ===");
    let trader_address_unchecked = trader_rpc.get_new_address(Some("Received"), None)?;
    let trader_address = trader_address_unchecked.require_network(Network::Regtest)
        .expect("Failed to set regtest network on trader address");
    println!("Trader receiving address: {}", trader_address);

    // Step 5: Send 20 BTC from Miner to Trader
    println!("\n=== Sending 20 BTC from Miner to Trader ===");
    let send_amount = Amount::from_btc(20.0).unwrap();
    
    // Create the transaction
    let txid = miner_rpc.send_to_address(
        &trader_address,
        send_amount,
        None, // comment
        None, // comment_to
        None, // subtract_fee_from_amount
        None, // replaceable
        None, // conf_target
        None, // estimate_mode
    )?;
    
    println!("Transaction sent with txid: {}", txid);

    // Step 6: Check transaction in mempool
    println!("\n=== Checking Transaction in Mempool ===");
    let mempool_entry: MempoolEntry = rpc.call("getmempoolentry", &[json!(txid.to_string())])?;
    println!("Transaction found in mempool:");
    println!("  TXID: {}", mempool_entry.txid);
    println!("  Base fee: {} BTC", mempool_entry.fees.base);

    // Step 7: Mine 1 block to confirm the transaction
    println!("\n=== Mining Block to Confirm Transaction ===");
    let confirmation_blocks = rpc.generate_to_address(1, &mining_address)?;
    let confirmation_block_hash = &confirmation_blocks[0];
    println!("Mined confirmation block: {}", confirmation_block_hash);

    // Step 8: Extract transaction details
    println!("\n=== Extracting Transaction Details ===");
    
    // Get transaction details with full information
    let tx_detail: TransactionDetail = miner_rpc.call("gettransaction", &[
        json!(txid.to_string()),
        json!(null), // include_watchonly
        json!(true)  // verbose (include decoded transaction)
    ])?;

    // Extract required information
    let transaction_id = tx_detail.txid;
    let block_hash = tx_detail.blockhash;
    let block_height = tx_detail.blockheight;
    let transaction_fee = tx_detail.fee.abs(); // Make sure fee is positive

    // Get input details (from the first vin which should be the miner's input)
    let input = &tx_detail.decoded.vin[0];
    let miner_input_address = input.prevout.as_ref()
        .and_then(|p| p.script_pub_key.address.as_ref())
        .expect("Could not find miner input address");
    let miner_input_amount = input.prevout.as_ref()
        .map(|p| p.value)
        .expect("Could not find miner input amount");

    // Find trader output (should be 20 BTC to trader address)
    let trader_output = tx_detail.decoded.vout.iter()
        .find(|vout| vout.script_pub_key.address.as_ref() == Some(&trader_address.to_string()))
        .expect("Could not find trader output");
    let trader_output_address = trader_address.to_string();
    let trader_output_amount = trader_output.value;

    // Find miner change output (the other output that's not to trader)
    let miner_change_output = tx_detail.decoded.vout.iter()
        .find(|vout| vout.script_pub_key.address.as_ref() != Some(&trader_address.to_string()))
        .expect("Could not find miner change output");
    let miner_change_address = miner_change_output.script_pub_key.address.as_ref()
        .expect("Miner change address not found");
    let miner_change_amount = miner_change_output.value;

    // Step 9: Write data to out.txt file
    println!("\n=== Writing Results to out.txt ===");
    
    let output_content = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        transaction_id,
        miner_input_address,
        miner_input_amount,
        trader_output_address,
        trader_output_amount,
        miner_change_address,
        miner_change_amount,
        transaction_fee,
        block_height,
        block_hash
    );

    // Write to out.txt in the project root (parent directory)
    let mut file = File::create("../out.txt")?;
    file.write_all(output_content.as_bytes())?;
    file.flush()?;

    println!("Transaction details written to out.txt");
    println!("\nSummary:");
    println!("- Transaction ID: {}", transaction_id);
    println!("- Miner input: {} BTC from {}", miner_input_amount, miner_input_address);
    println!("- Trader received: {} BTC at {}", trader_output_amount, trader_output_address);
    println!("- Miner change: {} BTC to {}", miner_change_amount, miner_change_address);
    println!("- Transaction fee: {} BTC", transaction_fee);
    println!("- Confirmed in block {} ({})", block_height, block_hash);

    Ok(())
}

// Helper function to create or load a wallet
fn create_or_load_wallet(rpc: &Client, wallet_name: &str) -> bitcoincore_rpc::Result<CreateWalletResult> {
    // Try to load the wallet first
    match rpc.load_wallet(wallet_name) {
        Ok(_) => {
            println!("Loaded existing wallet: {}", wallet_name);
            Ok(CreateWalletResult {
                name: wallet_name.to_string(),
                warning: None,
            })
        }
        Err(_) => {
            // If loading fails, try to create the wallet
            match rpc.create_wallet(wallet_name, None, None, None, None) {
                Ok(result) => {
                    println!("Created new wallet: {}", wallet_name);
                    Ok(CreateWalletResult {
                        name: result.name,
                        warning: result.warning,
                    })
                }
                Err(e) => {
                    // If creation also fails, it might already be loaded or there's another issue
                    println!("Warning: Could not create wallet {}: {:?}", wallet_name, e);
                    // Try to proceed assuming the wallet exists
                    Ok(CreateWalletResult {
                        name: wallet_name.to_string(),
                        warning: Some(format!("Could not create/load wallet: {:?}", e)),
                    })
                }
            }
        }
    }
}

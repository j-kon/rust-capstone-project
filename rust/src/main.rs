#![allow(unused)]
//! Bitcoin Capstone Project - RPC interaction with Bitcoin Core
//!
//! This program demonstrates comprehensive Bitcoin RPC operations including:
//! - Wallet creation and management
//! - Address generation with labels
//! - Block mining and coinbase maturity handling
//! - Transaction creation, mempool monitoring, and confirmation
//! - Transaction analysis and data extraction
//!
//! The program interacts with a Bitcoin Core node running in regtest mode,
//! which provides a controlled testing environment for Bitcoin development.

use bitcoin::hex::DisplayHex;
use bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

// Bitcoin Core RPC connection parameters
// These connect to a local Bitcoin Core node running in regtest mode
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port (mainnet: 8332, testnet: 18332)
const RPC_USER: &str = "alice"; // Username configured in bitcoin.conf
const RPC_PASS: &str = "password"; // Password configured in bitcoin.conf

// Custom deserializers for Bitcoin RPC responses
// These structs map JSON responses from Bitcoin Core RPC calls to Rust types

#[derive(Deserialize, Debug)]
struct CreateWalletResult {
    name: String,            // Name of the created/loaded wallet
    warning: Option<String>, // Any warnings from wallet creation
}

#[derive(Deserialize, Debug)]
struct GenerateToAddressResult {
    address: String,     // The address that received the block rewards
    blocks: Vec<String>, // Array of block hashes that were generated
}

#[derive(Deserialize, Debug)]
struct SendResult {
    complete: bool, // Whether the transaction was successfully created
    txid: String,   // Transaction ID of the created transaction
}

#[derive(Deserialize, Debug)]
struct MempoolEntry {
    #[serde(rename = "wtxid")]
    wtxid: String, // Witness transaction ID (includes witness data)
    fees: MempoolFees, // Fee information for the transaction
}

#[derive(Deserialize, Debug)]
struct MempoolFees {
    base: f64,       // Base fee in BTC
    modified: f64,   // Modified fee (for fee estimation)
    ancestor: f64,   // Total fees of ancestor transactions
    descendant: f64, // Total fees of descendant transactions
}

#[derive(Deserialize, Debug)]
struct TransactionDetail {
    txid: String,                // Transaction ID
    blockhash: String,           // Hash of the block containing this transaction
    blockheight: u64,            // Height of the block containing this transaction
    decoded: DecodedTransaction, // Detailed transaction data
    fee: Option<f64>,            // Transaction fee (may not always be available)
}

#[derive(Deserialize, Debug)]
struct DecodedTransaction {
    txid: String,                 // Transaction ID
    vin: Vec<TransactionInput>,   // Array of transaction inputs
    vout: Vec<TransactionOutput>, // Array of transaction outputs
}

#[derive(Deserialize, Debug)]
struct TransactionInput {
    txid: Option<String>, // ID of the transaction being spent (None for coinbase)
    vout: Option<u32>,    // Output index being spent (None for coinbase)
    #[serde(rename = "scriptSig")]
    script_sig: Option<ScriptSig>, // Signature script that unlocks the previous output
    sequence: Option<u32>, // Sequence number for transaction ordering
    txinwitness: Option<Vec<String>>, // Witness data for SegWit transactions
    prevout: Option<PrevOut>, // Information about the previous output being spent
}

#[derive(Deserialize, Debug)]
struct ScriptSig {
    asm: String, // Human-readable script assembly
    hex: String, // Hexadecimal representation of the script
}

#[derive(Deserialize, Debug)]
struct PrevOut {
    generated: Option<bool>, // Whether this output was from a coinbase transaction
    height: Option<u64>,     // Block height where this output was created
    value: f64,              // Value of the output in BTC
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey, // Script that defines spending conditions
}

#[derive(Deserialize, Debug)]
struct TransactionOutput {
    value: f64, // Value of this output in BTC
    n: u32,     // Output index within the transaction
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey, // Script that defines who can spend this output
}

#[derive(Deserialize, Debug)]
struct ScriptPubKey {
    asm: String, // Human-readable script assembly
    hex: String, // Hexadecimal representation of the script
    #[serde(rename = "type")]
    script_type: String, // Type of script (e.g., "pubkeyhash", "scripthash")
    address: Option<String>, // Bitcoin address (if applicable for this script type)
}

fn main() -> bitcoincore_rpc::Result<()> {
    // ========================================================================
    // INITIAL CONNECTION AND SETUP
    // ========================================================================

    // Establish connection to Bitcoin Core RPC server
    // This creates an authenticated client that can make RPC calls to the Bitcoin node
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    println!("Connected to Bitcoin Core RPC");

    // Get basic blockchain information to verify connection
    // This also shows the current state of the blockchain
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Current block height: {}", blockchain_info.blocks);

    // ========================================================================
    // STEP 1: WALLET CREATION AND MANAGEMENT
    // ========================================================================

    println!("\n=== Creating/Loading Wallets ===");

    // Create or load the Miner wallet
    // The Miner wallet will receive block rewards and send transactions
    let miner_wallet = create_or_load_wallet(&rpc, "Miner")?;
    println!("Miner wallet ready: {}", miner_wallet.name);

    // Create or load the Trader wallet
    // The Trader wallet will receive payments from the Miner wallet
    let trader_wallet = create_or_load_wallet(&rpc, "Trader")?;
    println!("Trader wallet ready: {}", trader_wallet.name);

    // Create wallet-specific RPC clients
    // These clients automatically route commands to the specific wallet
    let miner_rpc = Client::new(
        &format!("{RPC_URL}/wallet/Miner"),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    let trader_rpc = Client::new(
        &format!("{RPC_URL}/wallet/Trader"),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // ========================================================================
    // STEP 2: ADDRESS GENERATION FOR MINING REWARDS
    // ========================================================================

    println!("\n=== Generating Mining Address ===");

    // Generate a new address in the Miner wallet with a descriptive label
    // This address will receive block rewards when we mine blocks
    let mining_address_unchecked = miner_rpc.get_new_address(Some("Mining Reward"), None)?;

    // Ensure the address is configured for the regtest network
    // This is important for network validation and prevents mainnet/testnet confusion
    let mining_address = mining_address_unchecked
        .require_network(Network::Regtest)
        .expect("Failed to set regtest network on mining address");
    println!("Mining address generated: {mining_address}");

    // ========================================================================
    // STEP 3: BLOCK MINING AND COINBASE MATURITY
    // ========================================================================

    println!("\n=== Mining Blocks for Initial Balance ===");
    let mut blocks_mined = 0;
    let mut miner_balance = Amount::ZERO;

    // IMPORTANT: Bitcoin Coinbase Maturity Explanation
    // In Bitcoin, coinbase transaction outputs (block rewards) have a maturity period of 100 blocks
    // before they can be spent. This is a consensus rule that prevents issues if blocks are reorganized.
    // Therefore, we need to mine at least 101 blocks to have any spendable balance.
    //
    // This rule exists because:
    // 1. It prevents miners from spending rewards from blocks that might be orphaned
    // 2. It ensures network stability during potential blockchain reorganizations
    // 3. It's part of Bitcoin's consensus rules and applies to all networks (mainnet, testnet, regtest)

    while miner_balance == Amount::ZERO {
        // Mine a single block to the mining address using generatetoaddress RPC
        // This simulates the mining process and awards block rewards to our address
        let block_hashes = rpc.generate_to_address(1, &mining_address)?;
        blocks_mined += 1;

        // Check the wallet balance after mining
        // Balance will remain 0 until we reach coinbase maturity (101 blocks)
        miner_balance = miner_rpc.get_balance(None, None)?;

        // Progress reporting every 10 blocks to show the maturity process
        if blocks_mined % 10 == 0 {
            println!(
                "Mined {} blocks, current balance: {} BTC",
                blocks_mined,
                miner_balance.to_btc()
            );
        }

        // Safety mechanism to prevent infinite loops in case of unexpected behavior
        if blocks_mined > 200 {
            println!("Mined {blocks_mined} blocks, breaking to avoid infinite loop");
            break;
        }
    }

    println!("Mined {blocks_mined} blocks to achieve positive balance");
    println!("Miner wallet balance: {} BTC", miner_balance.to_btc());

    // Coinbase maturity explanation comment for educational purposes
    // In Bitcoin, coinbase transaction outputs (block rewards) have a maturity period of 100 blocks
    // before they can be spent. This is a consensus rule that prevents issues if blocks are reorganized.
    // That's why we need to mine at least 101 blocks to have any spendable balance.

    // ========================================================================
    // STEP 4: TRADER WALLET ADDRESS GENERATION
    // ========================================================================

    println!("\n=== Creating Trader Receiving Address ===");

    // Generate a new receiving address in the Trader wallet
    // This address will receive the 20 BTC payment from the Miner wallet
    let trader_address_unchecked = trader_rpc.get_new_address(Some("Received"), None)?;

    // Ensure the address is configured for the regtest network
    let trader_address = trader_address_unchecked
        .require_network(Network::Regtest)
        .expect("Failed to set regtest network on trader address");
    println!("Trader receiving address: {trader_address}");

    // ========================================================================
    // STEP 5: TRANSACTION CREATION AND BROADCASTING
    // ========================================================================

    println!("\n=== Sending 20 BTC from Miner to Trader ===");

    // Define the amount to send (20 BTC as specified in requirements)
    let send_amount = Amount::from_btc(20.0).unwrap();

    // Create and broadcast the transaction using send_to_address RPC
    // This function handles:
    // - Input selection (choosing which UTXOs to spend)
    // - Fee calculation (automatically calculated)
    // - Change address creation (for remaining funds)
    // - Transaction signing (using wallet's private keys)
    // - Broadcasting to the network mempool
    let txid = miner_rpc.send_to_address(
        &trader_address, // Destination address
        send_amount,     // Amount to send
        None,            // Optional comment for sender
        None,            // Optional comment for recipient
        None,            // Whether to subtract fee from amount
        None,            // Whether transaction is replaceable (RBF)
        None,            // Target confirmation time for fee estimation
        None,            // Fee estimation mode
    )?;

    println!("Transaction sent with txid: {txid}");

    // ========================================================================
    // STEP 6: MEMPOOL MONITORING AND ANALYSIS
    // ========================================================================

    println!("\n=== Checking Transaction in Mempool ===");

    // Query the mempool to verify our transaction is waiting for confirmation
    // The mempool contains all unconfirmed transactions that nodes have received
    let mempool_entry: MempoolEntry = rpc.call("getmempoolentry", &[json!(txid.to_string())])?;
    println!("Transaction found in mempool:");
    println!("  TXID: {txid}");
    println!("  Base fee: {} BTC", mempool_entry.fees.base);

    // Store the fee from mempool for later use in case gettransaction doesn't include it
    // Different Bitcoin Core versions may or may not include fee information in gettransaction
    let mempool_fee = mempool_entry.fees.base;

    // ========================================================================
    // STEP 7: TRANSACTION CONFIRMATION THROUGH MINING
    // ========================================================================

    println!("\n=== Mining Block to Confirm Transaction ===");

    // Mine a single block to confirm our transaction
    // This moves the transaction from mempool into a block on the blockchain
    let confirmation_blocks = rpc.generate_to_address(1, &mining_address)?;
    let confirmation_block_hash = &confirmation_blocks[0];
    println!("Mined confirmation block: {confirmation_block_hash}");

    // ========================================================================
    // STEP 8: DETAILED TRANSACTION ANALYSIS AND DATA EXTRACTION
    // ========================================================================

    println!("\n=== Extracting Transaction Details ===");

    // Retrieve comprehensive transaction information using gettransaction RPC
    // The verbose flag provides decoded transaction data including inputs and outputs
    let tx_detail: TransactionDetail = miner_rpc.call(
        "gettransaction",
        &[
            json!(txid.to_string()), // Transaction ID to query
            json!(null),             // include_watchonly (not needed here)
            json!(true),             // verbose = true (include decoded transaction)
        ],
    )?;

    // Extract basic transaction metadata
    let transaction_id = tx_detail.txid; // Transaction identifier
    let block_hash = tx_detail.blockhash; // Hash of containing block
    let block_height = tx_detail.blockheight; // Block height (number)

    // Extract transaction fee with fallback to mempool data
    // Some Bitcoin Core versions may not include fee in gettransaction response
    let transaction_fee = tx_detail.fee.unwrap_or(mempool_fee).abs();

    // ========================================================================
    // INPUT ANALYSIS: FINDING THE MINER'S SPENDING ADDRESS AND AMOUNT
    // ========================================================================

    // Get the first input (should be from the Miner wallet)
    let input = &tx_detail.decoded.vin[0];

    // Bitcoin transactions spend previous outputs (UTXOs). To find the input address,
    // we need to look up the previous transaction and find the output being spent.
    let (miner_input_address, miner_input_amount) = if let (Some(prev_txid), Some(prev_vout)) =
        (&input.txid, input.vout)
    {
        // Method 1: Query the previous transaction to get input details
        // This is necessary when prevout information isn't included in the response
        let prev_tx_detail: TransactionDetail = miner_rpc.call(
            "gettransaction",
            &[
                json!(prev_txid), // Previous transaction ID
                json!(null),      // include_watchonly
                json!(true),      // verbose = true
            ],
        )?;

        // Find the specific output from the previous transaction that this input spends
        let prev_output = &prev_tx_detail.decoded.vout[prev_vout as usize];
        let address = prev_output
            .script_pub_key
            .address
            .as_ref()
            .expect("Could not find address in previous output")
            .to_string();
        let amount = prev_output.value;

        (address, amount)
    } else {
        // Method 2: Fallback to prevout data if available
        // Some RPC responses include prevout information directly
        if let Some(prevout) = &input.prevout {
            let address = prevout
                .script_pub_key
                .address
                .as_ref()
                .expect("Could not find miner input address")
                .to_string();
            let amount = prevout.value;
            (address, amount)
        } else {
            panic!("Could not find miner input address - no prevout or previous transaction info");
        }
    };

    // ========================================================================
    // OUTPUT ANALYSIS: FINDING TRADER PAYMENT AND MINER CHANGE
    // ========================================================================

    // Find the trader output (should be exactly 20 BTC to trader address)
    // Bitcoin transactions can have multiple outputs, so we search for our specific payment
    let trader_output = tx_detail
        .decoded
        .vout
        .iter()
        .find(|vout| vout.script_pub_key.address.as_ref() == Some(&trader_address.to_string()))
        .expect("Could not find trader output");
    let trader_output_address = trader_address.to_string();
    let trader_output_amount = trader_output.value;

    // Find the miner change output (the remaining funds returned to miner)
    // When spending UTXOs, any unspent amount becomes "change" returned to the sender
    // This is the output that's NOT going to the trader
    let miner_change_output = tx_detail
        .decoded
        .vout
        .iter()
        .find(|vout| vout.script_pub_key.address.as_ref() != Some(&trader_address.to_string()))
        .expect("Could not find miner change output");
    let miner_change_address = miner_change_output
        .script_pub_key
        .address
        .as_ref()
        .expect("Miner change address not found");
    let miner_change_amount = miner_change_output.value;

    // ========================================================================
    // STEP 9: DATA OUTPUT AND RESULT FORMATTING
    // ========================================================================

    println!("\n=== Writing Results to out.txt ===");

    // Format the output data according to specification requirements
    // Each piece of data goes on a separate line in the exact order specified
    let output_content = format!(
        "{transaction_id}\n{miner_input_address}\n{miner_input_amount}\n{trader_output_address}\n{trader_output_amount}\n{miner_change_address}\n{miner_change_amount}\n{transaction_fee}\n{block_height}\n{block_hash}"
    );

    // Write to out.txt in the project root directory
    // This file will be used by the autograder to verify our results
    let mut file = File::create("../out.txt")?;
    file.write_all(output_content.as_bytes())?;
    file.flush()?; // Ensure data is written to disk immediately

    // Display a comprehensive summary for verification
    println!("Transaction details written to out.txt");
    println!("\nSummary:");
    println!("- Transaction ID: {transaction_id}");
    println!("- Miner input: {miner_input_amount} BTC from {miner_input_address}");
    println!("- Trader received: {trader_output_amount} BTC at {trader_output_address}");
    println!("- Miner change: {miner_change_amount} BTC to {miner_change_address}");
    println!("- Transaction fee: {transaction_fee} BTC");
    println!("- Confirmed in block {block_height} ({block_hash})");

    Ok(())
}

// ========================================================================
// HELPER FUNCTIONS
// ========================================================================

/// Creates a new wallet or loads an existing one with the given name
///
/// This function implements a robust wallet management strategy:
/// 1. First attempts to load an existing wallet (in case it was created previously)
/// 2. If loading fails, attempts to create a new wallet
/// 3. If both operations fail, returns a warning but continues execution
///
/// Parameters:
/// - rpc: Bitcoin Core RPC client for making wallet operations
/// - wallet_name: The name of the wallet to create or load
///
/// Returns: CreateWalletResult containing wallet name and any warnings
fn create_or_load_wallet(
    rpc: &Client,
    wallet_name: &str,
) -> bitcoincore_rpc::Result<CreateWalletResult> {
    // Attempt to load the wallet first (handles case where wallet already exists)
    match rpc.load_wallet(wallet_name) {
        Ok(_) => {
            println!("Loaded existing wallet: {wallet_name}");
            Ok(CreateWalletResult {
                name: wallet_name.to_string(),
                warning: None,
            })
        }
        Err(_) => {
            // If loading fails, try to create a new wallet
            match rpc.create_wallet(wallet_name, None, None, None, None) {
                Ok(result) => {
                    println!("Created new wallet: {wallet_name}");
                    Ok(CreateWalletResult {
                        name: result.name,
                        warning: result.warning,
                    })
                }
                Err(e) => {
                    // If creation also fails, log warning but continue
                    // This handles edge cases where wallet might be loaded but RPC calls fail
                    println!("Warning: Could not create wallet {wallet_name}: {e:?}");
                    Ok(CreateWalletResult {
                        name: wallet_name.to_string(),
                        warning: Some(format!("Could not create/load wallet: {e:?}")),
                    })
                }
            }
        }
    }
}

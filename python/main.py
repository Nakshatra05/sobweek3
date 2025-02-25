import os  # Provides functions for interacting with the operating system (e.g., file handling)
import json  # Used for parsing transaction data stored in JSON format
import hashlib  # Used for hashing operations (SHA-256)
import time  # Provides time-related functions (e.g., timestamping)
from binascii import unhexlify  # Converts hexadecimal strings to raw binary data

# Define the mining difficulty target. The block hash must be lower than this value.
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"

# Define the directory where pending transactions (mempool) are stored.
MEMPOOL_DIR = "mempool"

def load_transactions():
    """
    Load transactions from the mempool directory and validate them.
    
    Returns:
        list: A list of valid transactions (each transaction is a dictionary).
    """
    transactions = []
    for filename in os.listdir(MEMPOOL_DIR):  # Iterate over all transaction files in the mempool
        with open(os.path.join(MEMPOOL_DIR, filename), 'r') as file:
            tx = json.load(file)  # Load transaction JSON data
            if validate_transaction(tx):  # Validate transaction structure
                transactions.append(tx)  # Add valid transactions to the list
    return transactions  # Return the list of valid transactions

def validate_transaction(tx):
    """
    Validate if a transaction has the required fields.
    
    Args:
        tx (dict): The transaction data.
    
    Returns:
        bool: True if valid, False otherwise.
    """
    required_fields = {"txid", "fee", "size"}  # Required transaction attributes
    return all(field in tx for field in required_fields)  # Ensure all required fields exist

def merkle_root(txids):
    """
    Compute the Merkle root of a list of transaction IDs.
    
    Args:
        txids (list): A list of transaction IDs (hex strings).
    
    Returns:
        str: The Merkle root hash.
    """
    if not txids:
        return "0" * 64  # If no transactions, return 64 zeroes
    
    while len(txids) > 1:
        if len(txids) % 2 == 1:
            txids.append(txids[-1])  # If odd number of transactions, duplicate the last one
        
        # Compute the SHA-256 hash of each pair of transaction IDs
        txids = [
            hashlib.sha256(hashlib.sha256(unhexlify(a) + unhexlify(b)).digest()).hexdigest()
            for a, b in zip(txids[0::2], txids[1::2])
        ]
    
    return txids[0]  # Final remaining hash is the Merkle root

def mine_block(transactions):
    """
    Simulate mining a block by selecting transactions, constructing a Merkle root, and finding a valid hash.
    
    Args:
        transactions (list): A list of valid transactions.
    """
    # Sort transactions by highest fee-per-byte (priority order)
    transactions.sort(key=lambda x: x["fee"] / x["size"], reverse=True)

    # Select the top transactions that fit in a block (assuming a simple block size limit of 10 transactions)
    selected_transactions = transactions[:10]  

    # Create a dummy coinbase transaction (reward transaction for the miner)
    coinbase_tx = {
        "txid": hashlib.sha256(b"coinbase").hexdigest(),  # Simulated coinbase transaction ID
        "hex": "010000000001...",  # Placeholder for a real coinbase transaction (hex-encoded)
        "fee": 0,
        "size": 100
    }
    
    # Insert the coinbase transaction at the beginning of the block
    selected_transactions.insert(0, coinbase_tx)

    # Extract transaction IDs for Merkle root calculation
    txids = [tx["txid"] for tx in selected_transactions]
    merkle_root_hash = merkle_root(txids)  # Compute Merkle root

    # Use a sample valid hash as the previous block hash (in a real scenario, this would be fetched from the blockchain)
    prev_block_hash = "0000abcde12345f67890abcdef1234567890abcdef1234567890abcdef1234567"
    
    timestamp = int(time.time())  # Get the current timestamp
    nonce = 0  # Start nonce from 0

    # Proof-of-Work: Iterate until a valid hash (lower than the difficulty target) is found
    while True:
        # Construct the block header (concatenation of block components)
        block_header = f"{prev_block_hash}{merkle_root_hash}{timestamp:08x}{nonce:08x}"

        # Compute the SHA-256 hash of the block header twice
        block_hash = hashlib.sha256(hashlib.sha256(block_header.encode()).digest()).hexdigest()

        # Check if the computed hash meets the difficulty target
        if block_hash < DIFFICULTY_TARGET:
            break  # Valid block found, stop mining
        
        nonce += 1  # Increment nonce for the next attempt

    # Write the mined block details to an output file
    with open("out.txt", "w") as out_file:
        out_file.write(f"{block_header}\n")  # Block header
        out_file.write(f"{coinbase_tx['txid']}\n")  # Coinbase transaction ID
        
        # Write all included transaction IDs to the output file
        for tx in selected_transactions:
            out_file.write(f"{tx['txid']}\n")

def main():
    """
    Main function to load transactions and start mining.
    """
    transactions = load_transactions()  # Load transactions from the mempool
    mine_block(transactions)  # Start mining a block with the valid transactions

if __name__ == "__main__":
    main()  # Run the main function when the script is executed
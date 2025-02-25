import os
import json
import hashlib
import time
import struct
from binascii import unhexlify, hexlify

DIFFICULTY_TARGET = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
MEMPOOL_DIR = "mempool"
BLOCK_SIZE_LIMIT = 4000000  # Block weight limit (WU)


def load_transactions():
    """Load and validate transactions from the mempool folder."""
    transactions = []
    for filename in os.listdir(MEMPOOL_DIR):
        with open(os.path.join(MEMPOOL_DIR, filename), 'r') as file:
            try:
                tx = json.load(file)
                if all(field in tx for field in {"txid", "fee", "size", "weight"}):
                    transactions.append(tx)
            except json.JSONDecodeError:
                continue  # Skip invalid transactions
    return transactions


def merkle_root(txids):
    """Compute the Merkle root of the given transaction IDs."""
    if not txids:
        return "0" * 64  # Return 64 zeroes if no transactions

    txids = [bytes.fromhex(txid)[::-1] for txid in txids]  # Convert to little-endian

    while len(txids) > 1:
        if len(txids) % 2 == 1:
            txids.append(txids[-1])  # Duplicate last hash if odd count
        
        txids = [
            hashlib.sha256(hashlib.sha256(a + b).digest()).digest()
            for a, b in zip(txids[0::2], txids[1::2])
        ]
    
    return hexlify(txids[0][::-1]).decode()  # Convert back to big-endian


def construct_coinbase_transaction(fee_total):
    """Construct a simple coinbase transaction."""
    coinbase_tx = f"coinbase{fee_total}".encode()
    txid = hashlib.sha256(hashlib.sha256(coinbase_tx).digest()).hexdigest()
    
    return {
        "txid": txid,
        "hex": "010000000001...",  # Placeholder hex
        "fee": 0,
        "size": 100,
        "weight": 400
    }


def mine_block(transactions):
    """Select transactions, create a block header, and mine it."""
    transactions.sort(key=lambda x: x["fee"] / x["size"], reverse=True)

    block_weight = 0
    selected_transactions = []
    total_fees = 0

    for tx in transactions:
        if block_weight + tx["weight"] > BLOCK_SIZE_LIMIT:
            break
        selected_transactions.append(tx)
        block_weight += tx["weight"]
        total_fees += tx["fee"]

    # Create the coinbase transaction
    coinbase_tx = construct_coinbase_transaction(total_fees)
    selected_transactions.insert(0, coinbase_tx)

    txids = [tx["txid"] for tx in selected_transactions]
    merkle_root_hash = merkle_root(txids)

    # Use a dummy previous block hash that meets the difficulty
    prev_block_hash = "0000ffff00000000000000000000000000000000000000000000000000000000"

    # Block header fields
    version = 4
    timestamp = int(time.time())
    bits = 0x1f00ffff  # Difficulty target
    nonce = 0

    # Mining loop
    while nonce < 2**32:  # Avoid infinite loop due to integer overflow
        header_bin = struct.pack(
            "<L32s32sLLL",
            version,
            bytes.fromhex(prev_block_hash)[::-1],  # Little-endian
            bytes.fromhex(merkle_root_hash)[::-1],  # Little-endian
            timestamp,
            bits,
            nonce
        )
        
        hash1 = hashlib.sha256(header_bin).digest()
        hash2 = hashlib.sha256(hash1).digest()
        block_hash = int.from_bytes(hash2, byteorder='big')  # Convert without reversing

        if block_hash < DIFFICULTY_TARGET:
            break
        nonce += 1

    if nonce >= 2**32:
        raise RuntimeError("Nonce overflow: No valid hash found under difficulty target.")

    # Write output
    with open("out.txt", "w") as out_file:
        out_file.write(f"{header_bin.hex()}\n")
        out_file.write(f"{coinbase_tx['txid']}\n")
        for tx in selected_transactions:
            out_file.write(f"{tx['txid']}\n")


def main():
    transactions = load_transactions()
    mine_block(transactions)


if __name__ == "__main__":
    main()

import time
from datetime import datetime
from typing import List, Dict

class Transaction:
    def __init__(self, sender: str, receiver: str, amount: float):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = time.time()
    
    def to_string(self) -> str:
        return f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"

class SHA256:
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _rotr(self, x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFFFFFFF

    def _sha256_transform(self, message: bytes) -> str:
        
        
        h = self.h[0] 
        for byte in message:
            h = (h + byte + self._rotr(h, 2)) & 0xFFFFFFFFFFFFF
        return format(h, '064x')

    def hash(self, text: str) -> str:
        return self._sha256_transform(text.encode())

class MerkleTree:
    def __init__(self, transactions: List[Transaction]):
        self.transactions = transactions
        self.hasher = SHA256()

    def _hash_pair(self, left: str, right: str) -> str:
        return self.hasher.hash(left + right)

    def build_tree(self) -> str:
        if not self.transactions:
            return self.hasher.hash("")

        leaves = [self.hasher.hash(tx.to_string()) for tx in self.transactions]
        
        while len(leaves) > 1:
            next_level = []
            for i in range(0, len(leaves) - 1, 2):
                next_level.append(self._hash_pair(leaves[i], leaves[i + 1]))
            if len(leaves) % 2:
                next_level.append(leaves[-1])
            leaves = next_level
            
        return leaves[0]

class Block:
    def __init__(self, transactions: List[Transaction], previous_hash: str):
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_root = MerkleTree(transactions).build_tree()
        self.nonce = 0
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        hasher = SHA256()
        block_content = f"{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}"
        return hasher.hash(block_content)

    def mine_block(self, difficulty: int = 4):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self._calculate_hash()

class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_tx = Transaction("Genesis", "Genesis", 0)
        genesis_block = Block([genesis_tx], "0" * 64)
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def add_block(self, transactions: List[Transaction]):
        if len(transactions) != 10:
            raise ValueError("Each block must contain exactly 10 transactions")
        
        new_block = Block(transactions, self.chain[-1].hash)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def validate_blockchain(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block._calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

            if current_block.merkle_root != MerkleTree(current_block.transactions).build_tree():
                return False

        return True

def create_sample_transactions() -> List[Transaction]:
    return [
        Transaction(f"Sender{i}", f"Receiver{i}", 100 + i)
        for i in range(10)
    ]

def main():
    blockchain = Blockchain(difficulty=4)
    
    for _ in range(3):
        transactions = create_sample_transactions()
        blockchain.add_block(transactions)
        
    is_valid = blockchain.validate_blockchain()
    print(f"Blockchain is valid: {is_valid}")
    
    for i, block in enumerate(blockchain.chain):
        print(f"\nBlock {i}:")
        print(f"Timestamp: {datetime.fromtimestamp(block.timestamp)}")
        print(f"Previous Hash: {block.previous_hash}")
        print(f"Merkle Root: {block.merkle_root}")
        print(f"Hash: {block.hash}")
        print(f"Nonce: {block.nonce}")

if __name__ == "__main__":
    main()


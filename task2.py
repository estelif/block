import time
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import random
import json
from base64 import b64encode, b64decode
from dataclasses import dataclass

def is_prime(n: int, k: int = 128) -> bool:
    if n <= 3: return n > 1
    if n % 2 == 0: return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
        
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        if n % 2 != 0 and is_prime(n): return n

@dataclass
class KeyPair:
    public_key: Tuple[int, int]  
    private_key: Tuple[int, int] 

class RSA:
    def generate_keypair(self, bits: int = 1024) -> KeyPair:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537  
        d = pow(e, -1, phi)  
        
        return KeyPair(
            public_key=(e, n),
            private_key=(d, n)
        )
    
    def encrypt(self, message: str, public_key: Tuple[int, int]) -> str:
        e, n = public_key
        message_bytes = message.encode()
        encrypted = pow(int.from_bytes(message_bytes, 'big'), e, n)
        return b64encode(encrypted.to_bytes((encrypted.bit_length() + 7) // 8, 'big')).decode()
    
    def decrypt(self, encrypted_message: str, private_key: Tuple[int, int]) -> str:
        d, n = private_key
        encrypted = int.from_bytes(b64decode(encrypted_message), 'big')
        decrypted = pow(encrypted, d, n)
        return decrypted.to_bytes((n.bit_length() + 7) // 8, 'big').decode(errors='ignore').rstrip('\x00')

class Transaction:
    def __init__(self, sender: str, receiver: str, amount: float):
        self.sender = sender  
        self.receiver = receiver  
        self.amount = amount
        self.timestamp = time.time()
        self.signature: Optional[str] = None
        self.sender_public_key: Optional[Tuple[int, int]] = None
    
    def to_string(self) -> str:
        return f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"

    def sign(self, private_key: Tuple[int, int], public_key: Tuple[int, int]) -> None:
        self.sender_public_key = public_key
        rsa = RSA()
        self.signature = rsa.encrypt(self.to_string(), private_key)
    
    def verify(self) -> bool:
        if not self.signature or not self.sender_public_key:
            raise ValueError("Transaction must be signed and include sender's public key")
        
        if str(self.sender_public_key) != self.sender:
            raise ValueError("Sender address must match public key")
            
        rsa = RSA()
        try:
            decrypted = rsa.decrypt(self.signature, self.sender_public_key)
            return decrypted == self.to_string()
        except:
            raise ValueError("Signature is wrong")

class SHA256:
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        self.k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]  # Shortened for brevity
        
    def _rotr(self, x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _sha256_transform(self, message: bytes) -> str:
        h = self.h[0]
        for byte in message:
            h = (h + byte + self._rotr(h, 2)) & 0xFFFFFFFF
        return format(h, '016x')

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

class Wallet:
    def __init__(self):
        self.rsa = RSA()
        self.keypair = self.rsa.generate_keypair()
        
    @property
    def address(self) -> str:
        return str(self.keypair.public_key)
        
    def create_transaction(self, receiver: str, amount: float) -> Transaction:
        tx = Transaction(self.address, receiver, amount)
        tx.sign(self.keypair.private_key, self.keypair.public_key)
        return tx
    
    def save_transaction(self, tx: Transaction, filename: str = "pending_transactions.json"):
        tx_dict = {
            "sender": tx.sender,
            "receiver": tx.receiver,
            "amount": tx.amount,
            "timestamp": tx.timestamp,
            "signature": tx.signature,
            "sender_public_key": tx.sender_public_key
        }
        
        try:
            with open(filename, 'r') as f:
                transactions = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            transactions = []
            
        transactions.append(tx_dict)
        with open(filename, 'w') as f:
            json.dump(transactions, f)

class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_wallet = Wallet()
        genesis_tx = genesis_wallet.create_transaction("Genesis", 0)
        genesis_block = Block([genesis_tx], "0" * 64)
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def add_block(self, transactions: List[Transaction]):
        if len(transactions) != 10:
            raise ValueError("Each block must contain exactly 10 transactions")
            
        for tx in transactions:
            if not tx.verify():
                raise ValueError("Invalid transaction found")
        
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

            for tx in current_block.transactions:
                if not tx.verify():
                    return False

        return True
        
    def process_pending_transactions(self, filename: str = "pending_transactions.json"):
        try:
            with open(filename, 'r') as f:
                pending_tx = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
            
        valid_transactions = []
        for tx_dict in pending_tx:
            tx = Transaction(tx_dict["sender"], tx_dict["receiver"], tx_dict["amount"])
            tx.timestamp = tx_dict["timestamp"]
            tx.signature = tx_dict["signature"]
            tx.sender_public_key = tuple(tx_dict["sender_public_key"])
            
            try:
                if tx.verify():
                    valid_transactions.append(tx)
            except ValueError as e:
                print(f"Invalid transaction: {e}")
                
            if len(valid_transactions) == 10:
                self.add_block(valid_transactions)
                valid_transactions = []
        
        with open(filename, 'w') as f:
            json.dump([], f)

def main():
    blockchain = Blockchain(difficulty=2)
    
    khadisha = Wallet()
    dayana = Wallet()
    block = Wallet()
    
    wallets = [khadisha, dayana,block]
    for _ in range(4):  
        for wallet in wallets:
            receiver = random.choice([w for w in wallets if w != wallet])
            amount = random.uniform(1, 100)
            
            tx = wallet.create_transaction(receiver.address, amount)
            wallet.save_transaction(tx)
    
    blockchain.process_pending_transactions()
    
    is_valid = blockchain.validate_blockchain()
    print(f"\nBlockchain is valid: {is_valid}")
    
    for i, block in enumerate(blockchain.chain):
        print(f"\nBlock {i}:")
        print(f"Timestamp: {datetime.fromtimestamp(block.timestamp)}")
        print(f"Previous Hash: {block.previous_hash}")
        print(f"Merkle Root: {block.merkle_root}")
        print(f"Hash: {block.hash}")
        print(f"Nonce: {block.nonce}")
        print("\nTransactions:")
        for tx in block.transactions:
            print(f"  {tx.sender} -> {tx.receiver}: {tx.amount}")

if __name__ == "__main__":
    main()


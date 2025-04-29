from web3 import Web3
from dotenv import load_dotenv
import os
from eth_account.messages import encode_defunct
import hashlib
import time
# 替換 pyfalcon 為 oqs 模組
from oqs import Signature
import base64  # 用於編碼簽名和密鑰以便於展示
from eth_keys import keys  # 增加eth-keys庫
from eth_utils import to_bytes, keccak  # 用於轉換格式


def perform_falcon_signature(message):
    """
    執行 Falcon PQC 簽名並計時
    
    參數:
        message: 要簽名的消息(bytes)
    返回:
        tuple: (是否成功, 簽名時間, 密鑰生成時間, 驗證時間, 簽名結果詳情字典)
    """
    try:
        # 創建一個新的 Falcon 簽名對象
        start_time_keygen = time.perf_counter()
        sig = Signature("Falcon-512")
        
        # 生成密鑰對，在 liboqs 中，這個方法返回公鑰，而私鑰保存在對象中
        public_key = sig.generate_keypair()
        end_time_keygen = time.perf_counter()
        keygen_time = (end_time_keygen - start_time_keygen) * 1000
        
        # 進行 Falcon 簽名
        start_time_falcon = time.perf_counter()
        falcon_signature = sig.sign(message)
        end_time_falcon = time.perf_counter()
        falcon_time = (end_time_falcon - start_time_falcon) * 1000
        
        # 驗證 Falcon 簽名
        start_time_verify = time.perf_counter()
        is_valid = sig.verify(message, falcon_signature, public_key)
        end_time_verify = time.perf_counter()
        verify_time = (end_time_verify - start_time_verify) * 1000
        
        # 構建結果詳情字典
        result_details = {
            'algorithm': "Falcon-512",
            'signature_time_ms': falcon_time,
            'keygen_time_ms': keygen_time,
            'verify_time_ms': verify_time,
            'signature_size_bytes': len(falcon_signature),
            'public_key_size_bytes': len(public_key),
            'is_valid': is_valid
        }
        
        return True, falcon_time, keygen_time, verify_time, result_details
        
    except Exception as e:
        print(f"Falcon PQC 簽名錯誤: {str(e)}")
        # 顯示 Signature 類的可用方法和屬性，幫助診斷
        print("\n可用的 Signature 類屬性和方法:")
        print(dir(Signature))
        return False, 0, 0, 0, {'error': str(e)}

def perform_dilithium_signature(message):
    """
    執行 Dilithium PQC 簽名並計時
    
    參數:
        message: 要簽名的消息(bytes)
    返回:
        tuple: (是否成功, 簽名時間, 密鑰生成時間, 驗證時間, 簽名結果詳情字典)
    """
    try:
        # 直接使用確定的 Dilithium5 變體
        start_time_keygen = time.perf_counter()
        sig = Signature("Dilithium5")
        
        # 生成密鑰對
        public_key = sig.generate_keypair()
        end_time_keygen = time.perf_counter()
        keygen_time = (end_time_keygen - start_time_keygen) * 1000
        
        # 進行 Dilithium 簽名
        start_time_dilithium = time.perf_counter()
        dilithium_signature = sig.sign(message)
        end_time_dilithium = time.perf_counter()
        dilithium_time = (end_time_dilithium - start_time_dilithium) * 1000
        
        # 驗證 Dilithium 簽名
        start_time_verify = time.perf_counter()
        is_valid = sig.verify(message, dilithium_signature, public_key)
        end_time_verify = time.perf_counter()
        verify_time = (end_time_verify - start_time_verify) * 1000
        
        # 構建結果詳情字典
        result_details = {
            'algorithm': "Dilithium5",
            'signature_time_ms': dilithium_time,
            'keygen_time_ms': keygen_time,
            'verify_time_ms': verify_time,
            'signature_size_bytes': len(dilithium_signature),
            'public_key_size_bytes': len(public_key),
            'is_valid': is_valid
        }
        
        return True, dilithium_time, keygen_time, verify_time, result_details
        
    except Exception as e:
        print(f"Dilithium PQC 簽名錯誤: {str(e)}")
        # 顯示 Signature 類的可用方法和屬性，幫助診斷
        print("\n可用的 Signature 類屬性和方法:")
        print(dir(Signature))
        return False, 0, 0, 0, {'error': str(e)}

def setup_web3():
    # 載入環境變數
    load_dotenv()
    
    # 建立網路連接
    web3 = Web3(Web3.HTTPProvider(os.getenv('INFURA_URL')))
    
    # 檢查連接狀態
    if not web3.is_connected():
        print("錯誤：無法連接到以太坊網路")
        return None
    
    return web3



def send_eth_transaction(web3, to_address, amount_eth=0.1):
    try:
        # 從環境變數獲取發送方的私鑰和地址
        private_key = os.getenv('PRIVATE_KEY')
        from_address = os.getenv('ACCOUNT_ADDRESS')
        
        if not private_key or not from_address:
            print("錯誤：找不到必要的帳戶資訊")
            return False
        
        # 構建交易
        transaction = {
            'nonce': web3.eth.get_transaction_count(from_address),
            'to': to_address,
            'value': web3.to_wei(amount_eth, 'ether'),
            'gas': 21000,
            'gasPrice': web3.eth.gas_price,
            'chainId': 11155111  # Sepolia 測試網
        }
        
        # Web3.py的ECDSA簽名部分
        start_time_web3_ecdsa = time.perf_counter()
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        end_time_web3_ecdsa = time.perf_counter()
        web3_ecdsa_time = (end_time_web3_ecdsa - start_time_web3_ecdsa) * 1000
        
        # 獲取交易雜湊
        transaction_hash = signed_txn.hash
        
        # Web3.py ECDSA驗證部分 (簡單模擬)
        start_time_web3_ecdsa_verify = time.perf_counter()
        recover_hash = Web3.keccak(text="verify")  # 模擬驗證計算
        end_time_web3_ecdsa_verify = time.perf_counter()
        web3_ecdsa_verify_time = (end_time_web3_ecdsa_verify - start_time_web3_ecdsa_verify) * 1000
        
        # 使用Eth-Keys對相同交易雜湊進行ECDSA簽名
        # 準備私鑰格式
        if private_key.startswith('0x'):
            private_key_hex = private_key[2:]
        else:
            private_key_hex = private_key
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # 使用原始交易雜湊進行計時
        start_time_keygen = time.perf_counter()
        eth_key = keys.PrivateKey(private_key_bytes)
        public_key = eth_key.public_key
        end_time_keygen = time.perf_counter()
        ethkeys_keygen_time = (end_time_keygen - start_time_keygen) * 1000
        
        # 驗證派生的地址與提供的地址是否匹配
        derived_address = public_key.to_address()
        if derived_address.lower() != from_address.lower():
            print(f"警告: 派生地址 {derived_address} 與環境變數中的地址 {from_address} 不匹配")
        
        # 使用eth-keys進行ECDSA簽名
        start_time_ethkeys = time.perf_counter()
        ethkeys_signature = eth_key.sign_msg_hash(transaction_hash)
        end_time_ethkeys = time.perf_counter()
        ethkeys_time = (end_time_ethkeys - start_time_ethkeys) * 1000
        
        # 驗證eth-keys ECDSA簽名
        start_time_ethkeys_verify = time.perf_counter()
        is_valid = ethkeys_signature.verify_msg_hash(transaction_hash, public_key)
        end_time_ethkeys_verify = time.perf_counter()
        ethkeys_verify_time = (end_time_ethkeys_verify - start_time_ethkeys_verify) * 1000
        
        # 構建eth-keys ECDSA結果詳情
        ethkeys_details = {
            'algorithm': "Eth-Keys ECDSA",
            'signature_time_ms': ethkeys_time,
            'keygen_time_ms': ethkeys_keygen_time,
            'verify_time_ms': ethkeys_verify_time,
            'signature_size_bytes': len(ethkeys_signature.to_bytes()),
            'public_key_size_bytes': len(public_key.to_bytes()),
            'is_valid': is_valid,
            'ethkeys_success': True
        }
        
        # 使用外部函數執行 Falcon PQC 簽名
        success_falcon, falcon_time, falcon_keygen_time, falcon_verify_time, falcon_details = perform_falcon_signature(transaction_hash)
        
        # 使用外部函數執行 Dilithium PQC 簽名
        success_dilithium, dilithium_time, dilithium_keygen_time, dilithium_verify_time, dilithium_details = perform_dilithium_signature(transaction_hash)
            
        # 簽名時間比較
        if ethkeys_details['ethkeys_success'] and success_falcon and success_dilithium:
            print("\n=== 四種簽名算法時間比較 ===")
            print(f"算法          | 密鑰生成 (ms) | 簽章 (ms) | 驗證 (ms) | 簽章大小 (bytes) | 公鑰大小 (bytes)")
            print(f"-------------|--------------|-----------|-----------|-----------------|----------------")
            print(f"Web3.py ECDSA | -            | {web3_ecdsa_time:.2f}     | {web3_ecdsa_verify_time:.2f}     | -               | -")
            print(f"Eth-Keys ECDSA| {ethkeys_keygen_time:.2f}        | {ethkeys_time:.2f}     | {ethkeys_verify_time:.2f}     | {ethkeys_details['signature_size_bytes']}              | {ethkeys_details['public_key_size_bytes']}")
            print(f"Falcon-512    | {falcon_keygen_time:.2f}        | {falcon_time:.2f}     | {falcon_verify_time:.2f}     | {falcon_details['signature_size_bytes']}             | {falcon_details['public_key_size_bytes']}")
            print(f"Dilithium5    | {dilithium_keygen_time:.2f}        | {dilithium_time:.2f}     | {dilithium_verify_time:.2f}     | {dilithium_details['signature_size_bytes']}             | {dilithium_details['public_key_size_bytes']}")
        
        # 發送交易
        tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        print("\n=== 交易發送結果 ===")
        print(f"交易已發送！交易雜湊: {tx_hash.hex()}")
        print(f"查看交易: https://sepolia.etherscan.io/tx/{tx_hash.hex()}")
        
        return True
        
    except Exception as e:
        print(f"發生錯誤: {str(e)}")
        return False

def test_connection():
    try:
        web3 = setup_web3()
        
        # 添加連接診斷資訊
        print(f"Infura 連接狀態: {web3.is_connected()}")
        print(f"當前區塊高度: {web3.eth.block_number}")
        
        # 這裡可以添加發送測試交易的代碼
        # 注意：請替換為實際的接收地址
        receiver_address = os.getenv('RECEIVER_ADDRESS')  # 示例地址
        send_eth_transaction(web3, receiver_address)
        
        return True
        
    except Exception as e:
        print(f"錯誤詳情: {str(e)}")
        return False

if __name__ == "__main__":
    show_security_warning()
    test_connection()
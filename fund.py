import time
import logging
from pprint import pprint
from io import BytesIO

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from bedrock.ecc import PrivateKey
from bedrock.rpc import testnet
from bedrock.helper import encode_varint, hash256, hash160, encode_base58_checksum, decode_base58, sha256
from bedrock.tx import Tx, TxIn, TxOut
from bedrock.script import p2sh_script, p2pkh_script, p2wpkh_script, p2wsh_script, Script, address_to_script_pubkey

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

secret = 58800187338825965989061197411175755305019286370732616970021105328088303800803
key = PrivateKey(secret)

# testnet
rpc_template = "http://%s:%s@%s:%s/wallet/%s"
rpc = AuthServiceProxy(rpc_template % ('bitcoin', 'python', 'localhost', 18332, ''))
wallet_rpc = AuthServiceProxy(rpc_template % ('bitcoin', 'python', 'localhost', 18332, 'bitboy'))
# regtest
# rpc_template = "http://%s:%s@%s:%s/wallet/%s"
# rpc = AuthServiceProxy(rpc_template % ('bitcoin', 'python', 'localhost', 18443, ''))
# wallet_rpc = AuthServiceProxy(rpc_template % ('bitcoin', 'python', 'localhost', 18443, 'bitboy'))

SAT_PER_COIN = 100_000_000


def import_addresses():
    args = [{
        "scriptPubKey": {
            "address": "mqXaZ1BLm3cefYsPcrjq5PmskEcr79esHx"
        }, 
        "timestamp": int(time.time() - 10000)
    }]
    print(rpc.importmulti(args))

def import_keys():
    # unused
    args = [{
        "keys": [
            "cRwQJXHEbxZKRXkDK4rfgTtjnBpEwMptContVfAnn6rt3iYG8g1p",
        ],
        "timestamp": int(time.time() - 10000)
    }]
    print(rpc.importmulti(args))


def p2pk_script():
    sec = key.point.sec(compressed=True)
    return Script(cmds=[sec, 172])

def p2sh_h160():
    redeem_script = p2pk_script()
    raw_redeem = redeem_script.raw_serialize()
    return hash160(raw_redeem)

def p2pkh_address():
    return key.point.address(True, True)

def p2sh_address():
    return key.point.address(True, True)

def p2wpkh_address():
    h160 = key.point.hash160()
    script_pubkey = p2wpkh_script(h160)
    return script_pubkey.address(testnet=True)

def p2wsh_address():
    witness_script = p2pk_script()
    script_pubkey = p2wsh_script(sha256(witness_script.raw_serialize()))
    return script_pubkey.address(testnet=True)

def generate(n):
    address = rpc.getnewaddress()
    rpc.generatetoaddress(n, address)

def create_output(address):
    # construct transaction
    amount = .001
    raw = rpc.createrawtransaction(
        [],
        [{address: amount}],
    )

    # fund transaction
    funded = rpc.fundrawtransaction(raw)['hex']

    # sign transaction
    signed = rpc.signrawtransactionwithwallet(funded)['hex']

    # broadcast transaction
    broadcasted = rpc.sendrawtransaction(signed)

    # mine next block
    generate(1)

    return broadcasted

def spend_output(output_type):
    unspent, vout = get_unspent(output_type)

    # inputs
    tx_in = TxIn(bytes.fromhex(unspent['txid']), vout)
    tx_ins = [tx_in]

    # outputs
    tx_outs = []
    fee = 500
    unspent_sat = int(unspent['vout'][vout]['value'] * SAT_PER_COIN)
    amount = unspent_sat - fee

    recipient_script_pubkey = address_to_script_pubkey(rpc.getnewaddress())
    recipient_out = TxOut(amount, recipient_script_pubkey)

    tx_outs = [recipient_out]

    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
    if 'w' in output_type:
        tx.segwit = True
    print('Unsigned:', tx.serialize().hex())
    if output_type == 'witness_v0_scripthash':
        witness_script = p2pk_script()
        tx.sign_input(0, key, witness_script=witness_script)
    else:
        tx.sign_input(0, key)
    print('Verifies:', tx.verify())
    raw = tx.serialize()
    r = rpc.sendrawtransaction(raw.hex())
    print('TXID:', r)


def create_p2sh_output():
    # create p2sh address
    address = p2sh_address()
    # construct transaction
    return create_output(address)

def spend_p2sh_output():
    unspent, vout = get_unspent('scripthash')

    # inputs
    tx_in = TxIn(bytes.fromhex(unspent['txid']), vout)
    tx_ins = [tx_in]

    # outputs
    tx_outs = []
    fee = 500
    unspent_sat = unspent['vout'][vout]['value'] * SAT_PER_COIN
    amount = int(unspent_sat / 2)
    change = amount - fee

    recipient_address = rpc.getnewaddress()
    recipient_h160 = decode_base58(recipient_address)
    recipient_script_pubkey = p2pkh_script(recipient_h160)
    recipient_out = TxOut(amount, recipient_script_pubkey)

    change_script_pubkey = p2pkh_script(key.point.hash160())
    change_out = TxOut(change, change_script_pubkey)

    tx_outs = [recipient_out, change_out]

    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
    redeem_script = p2pk_script()
    tx.sign_input(0, key, redeem_script)
    print(tx.verify())
    raw = tx.serialize()
    r = rpc.sendrawtransaction(raw.hex())
    print(r)

def spend_p2pkh_output():
    unspent, vout = get_unspent('pubkeyhash')

    # inputs
    tx_in = TxIn(bytes.fromhex(unspent['txid']), vout)
    tx_ins = [tx_in]

    # outputs
    tx_outs = []
    fee = 500
    unspent_sat = int(unspent['vout'][vout]['value'] * SAT_PER_COIN)
    amount = unspent_sat - fee

    recipient_address = rpc.getnewaddress()
    recipient_h160 = decode_base58(recipient_address)
    recipient_script_pubkey = p2pkh_script(recipient_h160)
    recipient_out = TxOut(amount, recipient_script_pubkey)

    tx_outs = [recipient_out]

    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
    print('unsigned')
    print(tx.serialize().hex())
    tx.sign_input(0, key)
    print(tx.verify())
    raw = tx.serialize()
    r = rpc.sendrawtransaction(raw.hex())
    print(r)

def create_p2wpkh_output():
    # create p2wpkh address
    address = p2wpkh_address()
    # construct transaction
    return create_output(address)

def spend_p2wpkh_output():
    unspent, vout = get_unspent('witness_v0_keyhash')

    # inputs
    tx_in = TxIn(bytes.fromhex(unspent['txid']), vout)
    tx_ins = [tx_in]

    # outputs
    tx_outs = []
    fee = 500
    unspent_sat = int(unspent['vout'][vout]['value'] * SAT_PER_COIN)
    amount = unspent_sat - fee

    recipient_script_pubkey = address_to_script_pubkey(rpc.getnewaddress())
    # recipient_h160 = decode_base58(recipient_address)
    # recipient_script_pubkey = p2pkh_script(recipient_h160)
    recipient_out = TxOut(amount, recipient_script_pubkey)

    tx_outs = [recipient_out]

    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True, segwit=True)
    print('unsigned')
    print(tx.serialize().hex())
    tx.sign_input(0, key)
    print(tx.verify())
    raw = tx.serialize()
    r = rpc.sendrawtransaction(raw.hex())
    print(r)

def create_p2wsh_output():
    # create p2wsh address
    address = p2wsh_address()
    # construct transaction
    return create_output(address)

def create_p2sh_p2wsh_output():
    pass

def create_p2sh_p2wpkh_output():
    pass


def get_unspent(type):
    unspents = wallet_rpc.listunspent()
    for unspent in unspents:
        tx = wallet_rpc.getrawtransaction(unspent['txid'], 1)
        if tx["vout"][unspent['vout']]['scriptPubKey']['type'] == type:
            return tx, unspent['vout']

def foo():
    address = p2sh_address()
    unspents = rpc.listunspent()
    for unspent in unspents:
        tx = rpc.getrawtransaction(unspent['txid'], 1)
        script_pubkey = tx['vout'][unspent['vout']]['scriptPubKey']
        if address in script_pubkey['addresses']:
            print(tx['txid'])

def create_wallet(generate=False):
    watch_only_name = 'bitboy'
    bitcoin_wallets = rpc.listwallets()
    if watch_only_name not in bitcoin_wallets:
        try:
            rpc.loadwallet(watch_only_name)
            print(f"Loaded watch-only Bitcoin Core wallet \"{watch_only_name}\"")
        except JSONRPCException as e:
            try:
                rpc.createwallet(watch_only_name, True)
                print(f"Created watch-only Bitcoin Core wallet \"{watch_only_name}\"")
            except JSONRPCException as e:
                raise Exception("Couldn't establish watch-only Bitcoin Core wallet")

    # export p2sh address
    addresses = [p2sh_address(), p2pkh_address(), p2wpkh_address(), p2wsh_address()]
    for address in addresses:
        r = wallet_rpc.importmulti([{
            "scriptPubKey": {"address": address},
            "timestamp": int(time.time() - 10000),
            "watchonly": True,
            "keypool": True,
            "internal": False,
        }])
        print("importmulti: ", r)

    if generate:
        print('mine')
        generate(150)

def wallet_list_unspent():
    return wallet_rpc.listunspent()

def p2sh_demo_regtest():
    print('create p2sh output')
    print(create_p2sh_output())
    print('spend p2sh output')
    spend_p2sh_output()

def p2sh_demo_testnet():
    print("create wallet")
    create_wallet()
    if not get_unspent('pubkeyhash'):
        # needed for spend_p2sh_output step. happens automatically w/ generate() in regtest ...
        print("fund this address:", key.point.address(True, True))
        return
    print('create p2sh output from our default wallet')
    print(create_p2sh_output())
    print('spend p2sh output using bitboy wallet')
    spend_p2sh_output()

def p2wpkh_demo_regtest():
    create_wallet()
    print('create p2wpkh output')
    print(create_p2wpkh_output())
    print('spend p2wpkh output')
    spend_p2wpkh_output()

def p2wsh_demo_regtest(generate):
    create_wallet(generate=generate)
    print('create p2wsh output')
    print(create_p2wsh_output())
    print('spend p2wsh output')
    spend_output('witness_v0_scripthash')

def get_p2wshs():
    txns = []
    unspents = wallet_rpc.listunspent()
    for unspent in unspents[::-1]:
        tx = wallet_rpc.getrawtransaction(unspent['txid'], 1)
        if tx["vout"][unspent['vout']]['scriptPubKey']['type'] == 'witness_v0_scripthash':
            txns.append(tx['vout'][unspent['vout']])
    return txns

if __name__ == '__main__':
    print(p2wsh_demo_regtest(False))
    # print(p2wpkh_demo_regtest())

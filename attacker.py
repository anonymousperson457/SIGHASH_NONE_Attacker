import requests
import binascii

# Bech32 implementation
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Compute Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand HRP for checksum."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify Bech32 checksum."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech):
    """Decode a Bech32 string."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        return None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    if not all(x in CHARSET for x in bech[pos+1:]):
        return None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits > 0:
        return None
    return ret

def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp or data is None:
        return None, None
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None:
        return None, None
    if data[0] > 16:
        return None, None
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return None, None
    return data[0], decoded

def read_varint(raw, offset):
    """Read variable-length integer."""
    b = raw[offset]
    offset += 1
    if b < 0xfd:
        return b, offset
    elif b == 0xfd:
        val = int.from_bytes(raw[offset:offset+2], 'little')
        return val, offset + 2
    elif b == 0xfe:
        val = int.from_bytes(raw[offset:offset+4], 'little')
        return val, offset + 4
    else:
        val = int.from_bytes(raw[offset:offset+8], 'little')
        return val, offset + 8

def encode_varint(n):
    """Encode variable-length integer."""
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def parse_tx(raw):
    """Parse raw transaction."""
    offset = 0
    version = int.from_bytes(raw[offset:offset+4], 'little')
    offset += 4
    segwit = False
    if raw[offset:offset+2] == b'\x00\x01':
        segwit = True
        offset += 2
    input_count, offset = read_varint(raw, offset)
    inputs = []
    for _ in range(input_count):
        prev_txid = raw[offset:offset+32][::-1].hex()
        offset += 32
        vout = int.from_bytes(raw[offset:offset+4], 'little')
        offset += 4
        script_size, offset = read_varint(raw, offset)
        script_sig = raw[offset:offset+script_size]
        offset += script_size
        sequence = int.from_bytes(raw[offset:offset+4], 'little')
        offset += 4
        inputs.append({'prev_txid': prev_txid, 'vout': vout, 'script_sig': script_sig, 'sequence': sequence})
    output_count, offset = read_varint(raw, offset)
    outputs = []
    for _ in range(output_count):
        value = int.from_bytes(raw[offset:offset+8], 'little')
        offset += 8
        pk_size, offset = read_varint(raw, offset)
        script_pk = raw[offset:offset+pk_size]
        offset += pk_size
        outputs.append({'value': value, 'script_pubkey': script_pk})
    witnesses = []
    if segwit:
        for _ in range(input_count):
            item_count, offset = read_varint(raw, offset)
            wit_items = []
            for __ in range(item_count):
                item_size, offset = read_varint(raw, offset)
                item = raw[offset:offset+item_size]
                offset += item_size
                wit_items.append(item)
            witnesses.append(wit_items)
    locktime = int.from_bytes(raw[offset:offset+4], 'little')
    offset += 4
    if offset != len(raw):
        raise ValueError("Extra bytes in transaction")
    return {
        'version': version,
        'segwit': segwit,
        'inputs': inputs,
        'outputs': outputs,
        'witnesses': witnesses if segwit else [],
        'locktime': locktime
    }

def extract_sighash(sig):
    """Extract sighash type from signature."""
    return sig[-1] if sig else None

def is_valid_p2wpkh(addr):
    """Validate a mainnet P2WPKH address."""
    if not addr.startswith('bc1q'):
        return False
    try:
        hrp, data = bech32_decode(addr)
        if hrp != 'bc' or data is None:
            return False
        if len(data) < 1:
            return False
        witver = data[0]
        decoded = convertbits(data[1:], 5, 8, False)
        if decoded is None:
            return False
        if witver != 0:
            return False
        if len(decoded) != 20:
            return False
        return True
    except Exception:
        return False

def serialize_tx(parsed, new_outputs):
    """Serialize transaction with new outputs."""
    raw = b''
    raw += parsed['version'].to_bytes(4, 'little')
    if parsed['segwit']:
        raw += b'\x00\x01'
    raw += encode_varint(len(parsed['inputs']))
    for inp in parsed['inputs']:
        raw += bytes.fromhex(inp['prev_txid'])[::-1]
        raw += inp['vout'].to_bytes(4, 'little')
        raw += encode_varint(len(inp['script_sig']))
        raw += inp['script_sig']
        raw += inp['sequence'].to_bytes(4, 'little')
    raw += encode_varint(len(new_outputs))
    for out in new_outputs:
        raw += out['value'].to_bytes(8, 'little')
        raw += encode_varint(len(out['script_pubkey']))
        raw += out['script_pubkey']
    if parsed['segwit']:
        for wit in parsed['witnesses']:
            raw += encode_varint(len(wit))
            for item in wit:
                raw += encode_varint(len(item))
                raw += item
    raw += parsed['locktime'].to_bytes(4, 'little')
    return raw

def main():
    """Main function to process and broadcast transaction."""
    txid = input("Enter TXID: ").strip()
    url = f"https://mempool.space/api/tx/{txid}/hex"
    resp = requests.get(url)
    if resp.status_code != 200:
        print("Error fetching tx:", resp.text)
        return
    raw_hex = resp.text
    try:
        raw = binascii.unhexlify(raw_hex)
    except:
        print("Invalid hex")
        return
    try:
        parsed = parse_tx(raw)
    except Exception as e:
        print("Parse error:", e)
        return
    # Check for SIGHASH_NONE in all inputs
    try:
        for i in range(len(parsed['inputs'])):
            sighash = None
            sig = None
            if parsed['segwit'] and parsed['witnesses']:
                wit = parsed['witnesses'][i]
                if len(wit) == 2:
                    sig = wit[0]
                else:
                    raise ValueError("Unsupported Segwit Input Type")
            else:
                ss = parsed['inputs'][i]['script_sig']
                if len(ss) == 0:
                    raise ValueError("No scriptSig")
                pos = 0
                sig_len = ss[pos]
                if sig_len >= 0x4c:
                    raise ValueError("Non-standard scriptSig")
                pos += 1
                sig = ss[pos:pos + sig_len]
                pos += sig_len
                pub_len = ss[pos]
                if pub_len >= 0x4c:
                    raise ValueError("Non-standard scriptSig")
                pos += 1
                if pos + pub_len != len(ss):
                    raise ValueError("Invalid scriptSig")
            sighash = extract_sighash(sig)
            if (sighash & 0x1f) != 0x02:
                raise ValueError("Not using SIGHASH_NONE")
    except Exception as e:
        print("Error Checking Signatures:", e)
        return
    # Calculate total input value
    total_in = 0
    for inp in parsed['inputs']:
        prev_url = f"https://mempool.space/api/tx/{inp['prev_txid']}"
        prev_resp = requests.get(prev_url)
        if prev_resp.status_code != 200:
            print("Error fetching prev tx:", prev_resp.text)
            return
        prev_json = prev_resp.json()
        value = prev_json['vout'][inp['vout']]['value']
        total_in += value
    # Ask for P2WPKH address
    while True:
        addr = input("Enter Your P2WPKH Address: ").strip()
        if is_valid_p2wpkh(addr):
            break
        print("Invalid P2WPKH Address")
    # Ask for fee
    while True:
        fee_str = input("Enter fees in BTC: ").strip()
        try:
            fee_btc = float(fee_str)
            fee_sats = int(fee_btc * 100000000)
            if fee_sats > 0 and fee_sats < total_in:
                break
        except:
            pass
        print("Invalid fee")
    out_amount = total_in - fee_sats
    # Create script_pubkey for P2WPKH
    witver, witprog = decode('bc', addr)
    if witprog is None:
        print("Failed to decode address")
        return
    script_pk = b'\x00\x14' + bytes(witprog)
    new_outputs = [{'value': out_amount, 'script_pubkey': script_pk}]
    # Construct new tx
    new_raw = serialize_tx(parsed, new_outputs)
    new_hex = new_raw.hex()
    # Broadcast
    broadcast_url = "https://mempool.space/api/tx"
    resp = requests.post(broadcast_url, data=new_hex)
    if resp.status_code == 200:
        print("Modified Tx Broadcasted TXID:", resp.text)
    else:
        print("Broadcast Error:", resp.text)

if __name__ == "__main__":
    main()

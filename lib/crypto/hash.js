'use strict';

var crypto = require('crypto');
const NobleHashing = require("@noble/hashes/blake3");
var BN = require('../crypto/bn');
var BufferWriter = require('../encoding/bufferwriter');
var BufferUtil = require('../util/buffer');
var $ = require('../util/preconditions');
var blake2b = require("blake2b-wasm");

var Hash = module.exports;

Hash.sha1 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return crypto.createHash('sha1').update(buf).digest();
};

Hash.sha1.blocksize = 512;

Hash.sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return crypto.createHash('sha256').update(buf).digest();
};

Hash.sha256.blocksize = 512;

Hash.sha256sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.sha256(Hash.sha256(buf));
};

Hash.ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return crypto.createHash('ripemd160').update(buf).digest();
};

const FixedPadKey = (key) => {
  const encoder = new TextEncoder();
  const fixedSizeKey = new Uint8Array(32);
  encoder.encodeInto(key, fixedSizeKey);
  return fixedSizeKey;
}

const TransactionSigningHash = FixedPadKey("TransactionSigningHash");
const TransactionHash = FixedPadKey("TransactionHash");
const TransactionID = FixedPadKey("TransactionID");
const TransactionSigningHashECDSA = FixedPadKey("TransactionSigningHashECDSA");
const BlockHash = FixedPadKey("BlockHash");
const ProofOfWorkHash = FixedPadKey("ProofOfWorkHash");
const HeavyHash = FixedPadKey("HeavyHash");
const MerkleBranchHash = FixedPadKey("MerkleBranchHash");

class Blake3HashWriter {
	constructor(key) {
    // blake
		this.hash = NobleHashing.blake3.create({ dkLen: 32, key: key })
    this.bufferWriter = new BufferWriter();
  }

  update(data) {
    // Assuming data is a Buffer. If not, convert it to Buffer.
    this.bufferWriter.write(data);
    this.hash.update(data);
  }

  digest() {
    // Get the BLAKE3 hash digest as a Buffer
    return this.hash.digest();
  }

  finalize() {
    return Buffer.from(this.hash.digest());
  }
}

Blake3HashWriter.prototype.writeUInt8 = function(value) {
	const buf = new BufferWriter();
	buf.writeUInt8(value);
	this.hash.update(buf.toBuffer());
}

Blake3HashWriter.prototype.writeUInt16LE = function(value) {
	const buf = new BufferWriter();
	buf.writeUInt16LE(value);
	this.hash.update(buf.toBuffer());
}

Blake3HashWriter.prototype.writeUInt32LE = function(value) {
	const buf = new BufferWriter();
	buf.writeUInt32LE(value);
	this.hash.update(buf.toBuffer());
}

Blake3HashWriter.prototype.writeUInt64LE = function(value) {
	const buf = new BufferWriter();
	buf.writeUInt64LEBN(BN.fromNumber(value));
	this.hash.update(buf.toBuffer());
}

Blake3HashWriter.prototype.writeVarBytes = function(buf) {
	this.writeUInt64LE(buf.length);
	this.hash.update(buf);
}

Blake3HashWriter.prototype.writeHash = function(buf) {
	this.hash.update(buf);
}


Hash.NewTransactionHashWriter = () => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionHash)
  return writer;
}

Hash.NewTransactionHash = (buf) => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionHash)
  writer.update(buf);
  return writer.finalize();
}

Hash.NewTransactionIDWriter = () => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionSigningHash)
  return writer;
}
Hash.NewTransactionID = (buf) => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionID)
  writer.update(buf);
  return writer.finalize();
}

Hash.NewTransactionSigningHashWriter = () => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionSigningHash)
  return writer;
}

Hash.NewTransactionSigningHash = (buf) => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(TransactionSigningHash)
  writer.update(buf);
  return writer.finalize();
}

Hash.NewBlockHash = (buf) => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(BlockHash)
  writer.update(buf);
  return writer.finalize();
}

Hash.MerkleBranchHash = (buf) => {
  // $.checkArgument(BufferUtil.isBuffer(buf));
  const writer = new Blake3HashWriter(MerkleBranchHash)
  writer.update(buf);
  return writer.finalize();
}

Hash.blake3 = function(buf) {
  // $.checkArgument(BufferUtil.isBuffer(buf));
	const hasher = NobleHashing.blake3.create();
	hasher.update(buf)
  return hasher.finalize(); 
}

Hash.blake2b = function(buf) {
  return blake2b(32).update(buf).digest; 
}

Hash.blake2b_256 = (buf, key)=>{
  return blake2b(32, key).update(buf).digest();
}

Hash.blake3blake3 = function(buf) {
  //$.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.blake3(Hash.blake3(buf));
}

Hash.sha256ripemd160 = function(buf) {
  //$.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.ripemd160(Hash.sha256(buf));
};

Hash.sha512 = function(buf) {
  //$.checkArgument(BufferUtil.isBuffer(buf));
  return crypto.createHash('sha512').update(buf).digest();
};

Hash.sha512.blocksize = 1024;

Hash.hmac = function(hashf, data, key) {
  //http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  //http://tools.ietf.org/html/rfc4868#section-2
  $.checkArgument(BufferUtil.isBuffer(data));
  $.checkArgument(BufferUtil.isBuffer(key));
  $.checkArgument(hashf.blocksize);

  var blocksize = hashf.blocksize / 8;

  if (key.length > blocksize) {
    key = hashf(key);
  } else if (key < blocksize) {
    var fill = Buffer.alloc(blocksize);
    fill.fill(0);
    key.copy(fill);
    key = fill;
  }

  var o_key = Buffer.alloc(blocksize);
  o_key.fill(0x5c);

  var i_key = Buffer.alloc(blocksize);
  i_key.fill(0x36);

  var o_key_pad = Buffer.alloc(blocksize);
  var i_key_pad = Buffer.alloc(blocksize);
  for (var i = 0; i < blocksize; i++) {
    o_key_pad[i] = o_key[i] ^ key[i];
    i_key_pad[i] = i_key[i] ^ key[i];
  }

  return hashf(Buffer.concat([o_key_pad, hashf(Buffer.concat([i_key_pad, data]))]));
};

Hash.blake3hmac = function(data, key) {
  return Hash.hmac(Hash.blake3, data, key);
};

Hash.sha256hmac = function(data, key) {
  return Hash.hmac(Hash.sha256, data, key);
};

Hash.sha512hmac = function(data, key) {
  return Hash.hmac(Hash.sha512, data, key);
};

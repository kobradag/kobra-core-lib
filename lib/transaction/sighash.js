'use strict';

var Signature = require('../crypto/signature');
var Script = require('../script');
var Output = require('./output');
var BufferWriter = require('../encoding/bufferwriter');
var BN = require('../crypto/bn');
var Hash = require('../crypto/hash');
var ECDSA = require('../crypto/ecdsa');
var Schnorr = require('../crypto/schnorr');
var $ = require('../util/preconditions');
var Interpreter = require('../script/interpreter');
var _ = require('lodash');
const JSUtil = require('../util/js');
//const { isBuffer } = require('lodash');


var SIGHASH_SINGLE_BUG = '0000000000000000000000000000000000000000000000000000000000000001';
var BITS_64_ON = 'ffffffffffffffff';

// By default, we sign with sighash_forkid
var DEFAULT_SIGN_FLAGS = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID;

function isSighashAnyoneCanPay(sighashType) {
	return (sighashType & Signature.SIGHASH_ANYONECANPAY) === Signature.SIGHASH_ANYONECANPAY;
}

function isSighashSingle(sighashType) {
	return (sighashType & 31) === Signature.SIGHASH_SINGLE;
}

function isSighashNone(sighashType) {
	return (sighashType & 31) === Signature.SIGHASH_NONE;
}

function zeroHash() {
	return Buffer.alloc(32)
}

function zeroSubnetworkID() {
	return Buffer.alloc(20)
}

function getPreviousOutputsHash(transaction, sighashType, reusedValues) {
	if (isSighashAnyoneCanPay(sighashType)) {
		return zeroHash()
	}

	if (_.isUndefined(reusedValues.previousOutputsHash)){
		const hashWriter = Hash.NewTransactionSigningHashWriter();
		transaction.inputs.forEach(input => hashOutpoint(hashWriter, input));
		reusedValues.previousOutputsHash = hashWriter.finalize()
	}

	return reusedValues.previousOutputsHash;
}

function getSequencesHash(transaction, sighashType, reusedValues) {
	if (isSighashSingle(sighashType) || isSighashAnyoneCanPay(sighashType) || isSighashNone(sighashType)) {
		return zeroHash()
	}

	if (_.isUndefined(reusedValues.sequencesHash)){
		const hashWriter = Hash.NewTransactionSigningHashWriter();
		transaction.inputs.forEach(input => hashWriter.writeUInt64LE(input.sequenceNumber));
		reusedValues.sequencesHash = hashWriter.finalize()
	}

	return reusedValues.sequencesHash;
}

function getSigOpCountsHash(transaction, sigHashType, reusedValues) {
	if (isSighashAnyoneCanPay(sigHashType)) {
		return zeroHash()
	}

	if (_.isUndefined(reusedValues.sigOpCountsHash)){
		const hashWriter = Hash.NewTransactionSigningHashWriter();
		transaction.inputs.forEach(input => hashWriter.writeUInt8(1));//input.script.getSignatureOperationsCount())//sigOpCount));
		reusedValues.sigOpCountsHash = hashWriter.finalize()
	}

	return reusedValues.sigOpCountsHash
}

function getOutputsHash(transaction, inputNumber, sighashType, reusedValues) {
	if (isSighashNone(sighashType)) {
		return zeroHash()
	}

	// SigHashSingle: If the relevant output exists - return its hash, otherwise return zero-hash
	if (isSighashSingle(sighashType)){
		if (inputNumber >= transaction.outputs.length){
			return zeroHash();
		}
		const hashWriter = Hash.NewTransactionSigningHashWriter();
		hashTxOut(writer, transaction.outputs[inputNumber])
		return hashWriter.finalize();
	}

	if (_.isUndefined(reusedValues.outputsHash)){
		const hashWriter = Hash.NewTransactionSigningHashWriter();
		transaction.outputs.forEach(output => hashTxOut(hashWriter, output));
		reusedValues.outputsHash = hashWriter.finalize()
	}

	return reusedValues.outputsHash;
}

function hashOutpoint(hashWriter, input) {
	hashWriter.writeHash(input.prevTxId);
	hashWriter.writeUInt32LE(input.outputIndex);
}

function hashTxOut(hashWriter, output) {
	hashWriter.writeUInt64LE(output.satoshis);
	hashWriter.writeUInt16LE(0); // TODO: USE REAL SCRIPT VERSION
	hashWriter.writeVarBytes(output.script.toBuffer());
}

/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for OP_CHECKSIG.
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Script} subscript the script that will be signed
 * @param {satoshisBN} input's amount (for  ForkId signatures)
 *
 */
function sighash(transaction, sighashType, inputNumber, subscript, satoshisBN, flags, reusedValues = {}) {
	const Transaction = require('./transaction');

	const hashWriter = Hash.NewTransactionSigningHashWriter();
	//hashWriter.L = true

	hashWriter.writeUInt16LE(transaction.version)
	hashWriter.writeHash(getPreviousOutputsHash(transaction, sighashType, reusedValues));
	hashWriter.writeHash(getSequencesHash(transaction, sighashType, reusedValues));
	hashWriter.writeHash(getSigOpCountsHash(transaction, sighashType, reusedValues))

	const input = transaction.inputs[inputNumber];
	hashOutpoint(hashWriter, input);
	hashWriter.writeUInt16LE(0); 																																	// TODO: USE REAL SCRIPT VERSION
	hashWriter.writeVarBytes(input.output.script.toBuffer());																			// Script
	hashWriter.writeUInt64LE(input.output.satoshis);																							// UTXOEntry amount
	hashWriter.writeUInt64LE(input.sequenceNumber);																								// Sequence number
	hashWriter.writeUInt8(1)																																			// sigOpCount	
	hashWriter.writeHash(getOutputsHash(transaction, inputNumber, sighashType, reusedValues));	  // Write output hashes
	hashWriter.writeUInt64LE(transaction.nLockTime);																							// Loc time
	hashWriter.writeHash(zeroSubnetworkID()); 																										// TODO: USE REAL SUBNETWORK ID
	hashWriter.writeUInt64LE(0); 																																	// TODO: USE REAL GAS
	hashWriter.writeHash(zeroHash()); 																														// TODO: USE REAL PAYLOAD HASH
	hashWriter.writeUInt8(sighashType);
	return hashWriter.finalize();
}


/**
 * Create a signature
 *
 * @name Signing.sign
 * @param {Transaction} transaction
 * @param {PrivateKey} privateKey
 * @param {number} sighash
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @param {signingMethod} signingMethod "ecdsa" or "schnorr" to sign a tx
 * @return {Signature}
 */
function sign(transaction, privateKey, sighashType, inputIndex, subscript, satoshisBN, flags, signingMethod) {
	//let ts0 = Date.now();
	var hashbuf = sighash(transaction, sighashType, inputIndex, subscript, satoshisBN, flags);
	//let ts1 = Date.now();
	//console.log("#### sighash.sign", "inputIndex:", inputIndex, "sighash time:", ts1-ts0)
	signingMethod = signingMethod || "ecdsa";
	let sig;

	if (signingMethod === "schnorr") {
		sig = Schnorr.sign(hashbuf, privateKey, 'little').set({
			nhashtype: sighashType
		});
		return sig;
	} else if (signingMethod === "ecdsa") {
		sig = ECDSA.sign(hashbuf, privateKey, 'little').set({
			nhashtype: sighashType
		});
		return sig;
	}
}

/**
 * Verify a signature
 *
 * @name Signing.verify
 * @param {Transaction} transaction
 * @param {Signature} signature
 * @param {PublicKey} publicKey
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @param {flags} verification flags
 * @param {signingMethod} signingMethod "ecdsa" or "schnorr" to sign a tx
 * @return {boolean}
 */
function verify(transaction, signature, publicKey, inputIndex, subscript, satoshisBN, flags, signingMethod) {
	$.checkArgument(!_.isUndefined(transaction));
	$.checkArgument(!_.isUndefined(signature) && !_.isUndefined(signature.nhashtype));
	var hashbuf = sighash(transaction, signature.nhashtype, inputIndex, subscript, satoshisBN, flags);

	signingMethod = signingMethod || "ecdsa";

	if (signingMethod === "schnorr") {
		return Schnorr.verify(hashbuf, signature, publicKey, 'little')
	} else if (signingMethod === "ecdsa") {
		return ECDSA.verify(hashbuf, signature, publicKey, 'little');
	}
}

/**
 * @namespace Signing
 */
module.exports = {
	sighash: sighash,
	sign: sign,
	verify: verify
};
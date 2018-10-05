package org.marcusbb.crypto;

import javax.crypto.spec.IvParameterSpec;

/**
 *
 * The contract of the VersionedKey has 2 general purposes
 * 1. That is serves as a representation of the naming of a
 * lookup of a key (keyHash)
 * 2. It represents a (portion) of some additional metadata of
 * the encrypted payload, and can help with reconstructing
 * part or all of the keyHash.
 *
 * <p>
 * It requires that the {@link #keyHash()} be built
 * and that corresponds to the lookup of that Key.
 *
 * {@link IvParameterSpec} is not technically part of the contract
 * of the key lookup, its the cipher's initialization vector,
 * but is a requirement for performing encryption/decryption
 *
 */
public interface VersionedKey {

	String keyHash();

	int headerLength();

	byte[] header();

	//Not sure that this is part of the key signature?
	IvParameterSpec iv();

	String versionedKeyName();

	int getVersion();
}

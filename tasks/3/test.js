import { Transaction, address, networks } from "bitcoinjs-lib";
import { promises as fs } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { serialize } from "v8";

// Paths - adjust these to your environment
const mempoolDir = "./mempool";
const outputFile = "./out.txt";
export const difficulty = Buffer.from(
  "0000ffff00000000000000000000000000000000000000000000000000000000",
  "hex"
);
export const WITNESS_RESERVED_VALUE = Buffer.from(
  // 32 bytes of zeros (0x00) for witness commitment calculation (BIP141)
  "0000000000000000000000000000000000000000000000000000000000000000",
  "hex"
);
export const hash256 = (input) => {
  // Double SHA256 hash function (returns Buffer)
  const h1 = createHash("sha256").update(Buffer.from(input, "hex")).digest();
  return createHash("sha256").update(h1).digest();
};
export const generateMerkleRoot = (txids) => {
  if (txids.length === 0) return null;

  // Txids should already be in little-endian format from blockchain
  // Make a copy of the array to avoid modifying the original
  let level = [...txids];

  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      let pair;
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pair = level[i] + level[i];
      } else {
        pair = level[i] + level[i + 1];
      }

      // Calculate hash and convert to hex
      const pairHash = hash256(pair).toString("hex");
      nextLevel.push(pairHash);
    }

    level = nextLevel;
  }

  // Return the hex string directly (not a Buffer)
  return level[0];
};
export const calculateWitnessCommitment = (wtxids) => {
  // Start with a coinbase wtxid of all zeros
  const coinbaseWtxid =
    "0000000000000000000000000000000000000000000000000000000000000000";

  // Create a new array with coinbase wtxid first, then other wtxids
  const allWtxids = [coinbaseWtxid, ...wtxids];

  const witnessRoot = generateMerkleRoot(allWtxids);
  console.log("Witness root:", witnessRoot);

  const witnessCommitment = hash256(
    witnessRoot + WITNESS_RESERVED_VALUE.toString("hex")
  ).toString("hex");

  console.log("Witness commitment:", witnessCommitment);
  return witnessCommitment;
};
function validateBitcoinTx(txJson) {
  console.log(`Validating transaction ${txJson.txid}...`);
  try {
    const tx = Transaction.fromHex(txJson.hex); // Parse the transaction JSON from hex string to Transaction object (from bitcoinjs-lib)
    const calculatedTxId = tx.getId();

    console.log(`  Calculated TXID: ${calculatedTxId}`);
    console.log(`  Expected TXID:   ${txJson.txid}`);

    if (calculatedTxId !== txJson.txid) {
      console.log(`  ❌ TXID mismatch!`);
      return {
        valid: false,
        error: `Invalid txid. Expected: ${txJson.txid}, Got: ${calculatedTxId}`,
      };
    }

    // Basic structure validation
    console.log(
      `  Input count: ${txJson.vin.length}, Output count: ${txJson.vout.length}`
    );
    if (
      !txJson.vin ||
      !txJson.vout ||
      txJson.vin.length !== tx.ins.length ||
      txJson.vout.length !== tx.outs.length
    ) {
      console.log(`  ❌ Input/output structure mismatch!`);
      return { valid: false, error: "Mismatch in vin/vout structure" };
    }

    // Validate inputs
    for (let i = 0; i < txJson.vin.length; i++) {
      const input = txJson.vin[i];
      if (
        !input.txid ||
        typeof input.vout !== "number" ||
        !input.prevout?.scriptpubkey
      ) {
        console.log(`  ❌ Invalid structure in input ${i}!`);
        return { valid: false, error: `Invalid structure in input ${i}` };
      }
    }

    // Validate outputs
    let totalOutput = 0;
    for (let i = 0; i < txJson.vout.length; i++) {
      const output = txJson.vout[i];
      if (!output.scriptpubkey || typeof output.value !== "number") {
        console.log(`  ❌ Invalid structure in output ${i}!`);
        return { valid: false, error: `Invalid structure in output ${i}` };
      }
      totalOutput += output.value;
    }

    // Calculate and verify the fee
    const totalInput = txJson.vin.reduce(
      (sum, input) => sum + (input.prevout?.value || 0),
      0
    );
    const expectedFee = totalInput - totalOutput;

    console.log(`  Total input: ${totalInput}, Total output: ${totalOutput}`);
    console.log(`  Expected fee: ${expectedFee}, Declared fee: ${txJson.fee}`);

    if (expectedFee !== txJson.fee) {
      console.log(`  ❌ Fee mismatch!`);
      return {
        valid: false,
        error: `Fee mismatch. Expected: ${expectedFee}, Got: ${txJson.fee}`,
      };
    }

    const weight = tx.weight();
    const feeRate = (txJson.fee / weight) * 4; // Fee per vByte

    console.log(`  Transaction weight: ${weight} WU`);
    console.log(`  Fee rate: ${feeRate.toFixed(2)} sat/vByte`);
    console.log(`  ✅ Transaction valid!`);

    return {
      valid: true,
      tx: txJson,
      weight,
      fee: txJson.fee,
      feeRate,
    };
  } catch (error) {
    console.log(`  ❌ Validation error: ${error.message}`);
    return { valid: false, error: `Validation failed: ${error.message}` };
  }
}
function createCoinbaseTransaction(blockHeight, totalFees, witnessCommitment) {
  console.log(`Creating coinbase transaction:`);
  console.log(`  Block height: ${blockHeight}`); // Example block height for coinbase transaction (BIP34) - 835000 in this case (arbitrary)
  //usage of block height in coinbase transaction is to make sure that the block is mined at the correct height and not at a different height
  console.log(`  Total fees: ${totalFees} satoshis`); // Total fees from all transactions in the block (including coinbase) - 1000 in this case (arbitrary) for testing purposes only (not real fees) - should be calculated from the transactions in the block (excluding coinbase)

  const tx = new Transaction();
  tx.version = 1; // SegWit transactions use version 1
  tx.locktime = 0;

  // BIP-34: Block height as a script number
  const heightBuffer = Buffer.alloc(4);
  heightBuffer.writeUInt32LE(blockHeight);

  // Create arbitrary coinbase data
  let coinbaseScript = Buffer.concat([
    heightBuffer,
    Buffer.from("/BTC Mining Simulator/", "utf8"),
  ]);

  // Include witness commitment in the coinbase script
  if (witnessCommitment) {
    const commitmentScript = Buffer.concat([
      Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]), // OP_RETURN + Witness commitment header
      Buffer.from(witnessCommitment, "hex"),
    ]);
    coinbaseScript = Buffer.concat([coinbaseScript, commitmentScript]);
  }

  console.log(`  Coinbase script: ${coinbaseScript.toString("hex")}`);

  // Add input (coinbase has no real input)
  tx.addInput(Buffer.alloc(32, 0), 0xffffffff);
  tx.setInputScript(0, coinbaseScript);

  // Add witness reserved value as the first witness item
  tx.ins[0].witness = [WITNESS_RESERVED_VALUE];

  // Block reward (current is 3.125 BTC after 2024 halving)
  const subsidy = 312500000; // 3.125 BTC in satoshis
  const totalReward = subsidy + totalFees;

  console.log(`  Block subsidy: ${subsidy} satoshis`);
  console.log(`  Total reward: ${totalReward} satoshis`);

  // Add output to a standard address
  const rewardAddress = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"; // Example address
  const rewardScript = address.toOutputScript(rewardAddress, networks.bitcoin);

  console.log(`  Reward address: ${rewardAddress}`);
  console.log(`  Output script: ${rewardScript.toString("hex")}`);

  tx.addOutput(rewardScript, totalReward);

  // Add second output for witness commitment
  const witnessCommitmentScript = Buffer.from([
    0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed,
  ]); // OP_RETURN + Witness commitment header
  tx.addOutput(witnessCommitmentScript, 0); // Zero value output

  const txHex = tx.toHex();
  const txid = tx.getId();

  console.log(`  Coinbase TXID: ${txid}`);
  console.log(`  Coinbase hex size: ${txHex.length / 2} bytes`);

  return tx;
}
function serializeCoinbaseTransaction(tx) {
  // Version (4 bytes, little-endian)
  const version = Buffer.alloc(4);
  version.writeUInt32LE(tx.version);

  // Input Count (VarInt, always 0x01 for coinbase)
  const inputCount = Buffer.from("01", "hex");

  // Input
  const prevOutputHash = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "hex"
  );// Null txid for coinbase input (32 bytes) - all zeros
  const prevOutputIndex = Buffer.from("ffffffff", "hex");

  // ScriptSig (coinbase script)
  const scriptSig = tx.ins[0].script;
  const scriptSigLength = Buffer.from([scriptSig.length]);

  // Sequence (4 bytes, usually 0xffffffff)
  const sequence = Buffer.from("ffffffff", "hex");

  // Combine input fields
  const input = Buffer.concat([
    prevOutputHash,
    prevOutputIndex,
    scriptSigLength,
    scriptSig,
    sequence,
  ]);

  // Output Count (VarInt)
  const outputCount = Buffer.from([tx.outs.length]);

  // Outputs
  const outputs = tx.outs.map((output) => {
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(BigInt(output.value));

    const scriptPubKey = output.script;
    const scriptPubKeyLength = Buffer.from([scriptPubKey.length]);

    return Buffer.concat([value, scriptPubKeyLength, scriptPubKey]);
  });

  // Locktime (4 bytes, usually 0x00000000)
  const locktime = Buffer.alloc(4);
  locktime.writeUInt32LE(tx.locktime);

  // Combine all fields
  const serializedTx = Buffer.concat([
    version,
    inputCount,
    input,
    outputCount,
    ...outputs,
    locktime,
  ]);

  return serializedTx;
}
function createBlockHeader(prevBlockHash, merkleRoot, timestamp, bits, nonce) {
  console.log(`Creating block header:`);
  console.log(`  Version: 0x20000000 (BIP9 signaling)`);
  console.log(`  Previous block: ${prevBlockHash}`);
  console.log(`  Merkle root: ${merkleRoot.toString("hex")}`);
  console.log(
    `  Timestamp: ${timestamp} (${new Date(timestamp * 1000).toISOString()})`
  );
  console.log(`  Bits: ${bits}`);
  console.log(`  Initial nonce: ${nonce}`);

  // Bitcoin block version 0x20000000 (with BIP9 signaling)
  const version = 0x20000000;

  const header = Buffer.alloc(80);

  // All fields need to be in little-endian format
  header.writeUInt32LE(version, 0);
  Buffer.from(prevBlockHash, "hex").reverse().copy(header, 4);

  Buffer.from(merkleRoot, "hex").reverse().copy(header, 36);
  header.writeUInt32LE(timestamp, 68);
  Buffer.from(bits, "hex").reverse().copy(header, 72);
  header.writeUInt32LE(nonce, 76);

  console.log(`  Header hex: ${header.toString("hex")}`);
  return header;
}
function mineBlock(header, target) {
  console.log(`Starting mining process...`);
  console.log(`  Target: ${target.toString("hex")}`);

  let nonce = 0;
  const startTime = Date.now();

  while (true) {
    // Update nonce in the header (last 4 bytes)
    header.writeUInt32LE(nonce, 76);

    // Double SHA256 hash
    const hash1 = hash256(header);

    // Check if hash is below target (valid block)
    if (Buffer.compare(hash1, target) < 0) {
      const timeTaken = (Date.now() - startTime) / 1000;
      const hashRate = nonce / timeTaken;

      console.log(`  ✅ Block found!`);
      console.log(`  Nonce: ${nonce}`);
      console.log(`  Block hash: ${hash1.reverse().toString("hex")}`);
      console.log(`  Time taken: ${timeTaken.toFixed(2)} seconds`);
      console.log(`  Hash rate: ${Math.floor(hashRate)} hashes/second`);

      return {
        header: header.toString("hex"),
        hash: hash1.reverse().toString("hex"),
        nonce,
      };
    }

    nonce++;
    if (nonce % 100000 === 0) { // Log progress every 100k hashes (optional) 
      const elapsed = (Date.now() - startTime) / 1000;
      const hashRate = nonce / elapsed;
      console.log(
        `  Mining progress: ${nonce} hashes, ${Math.floor(
          hashRate
        )} hashes/second`
      );
    }

    if (nonce > 0xffffffff) { // 32-bit nonce limit
      console.log(`  ⚠️ Nonce overflow!`);
      throw new Error("Nonce overflow");
    }
  }
}
async function processAndMineBlock() {
  console.log(`=== BITCOIN MINING SIMULATION ===`);
  try {
    // 1. Read and validate transactions from mempool
    console.log(`Reading transactions from mempool directory: ${mempoolDir}`);
    const files = await fs.readdir(mempoolDir);
    const jsonFiles = files.filter((file) => file.endsWith(".json"));

    // Store mempool transaction IDs for validation
    const mempoolTxids = new Set();
    jsonFiles.forEach((file) => {
      // Extract txid from filename
      const txid = file.replace(".json", "");
      mempoolTxids.add(txid);
    });

    console.log(`Found ${jsonFiles.length} transaction files`);

    if (jsonFiles.length === 0) {
      throw new Error("No transactions found in mempool");
    }

    // Limit to max 5 transactions for easier debugging
    const MAX_TX_COUNT = 3;
    const selectedFiles = jsonFiles.slice(0, MAX_TX_COUNT);
    console.log(
      `Processing ${selectedFiles.length} transactions for validation`
    );

    // When selecting transactions, check if they're in mempool
    const validTxs = [];
    const wtxids = [];
    let totalWeight = 0;
    const MAX_BLOCK_WEIGHT = 4000000; // 4M weight units

    for (const file of selectedFiles) {
      const filePath = join(mempoolDir, file);
      console.log(`Reading file: ${filePath}`);

      const fileContent = await fs.readFile(filePath, "utf8");
      const txJson = JSON.parse(fileContent);

      const result = validateBitcoinTx(txJson);
      if (result.valid && mempoolTxids.has(txJson.txid)) {
        // Check if adding this transaction would exceed max block weight
        if (totalWeight + result.weight <= MAX_BLOCK_WEIGHT) {
          validTxs.push({
            ...result,
            txid: txJson.txid,
            hex: txJson.hex,
          });
          totalWeight += result.weight;
          console.log(
            `Added transaction ${txJson.txid} to valid set (weight: ${result.weight})`
          );

          // Calculate wtxid if witness data is present
          if (txJson.witness) {
            const wtxid = hash256(txJson.hex); // Double SHA256 of transaction hex string (without witness data) for wtxid calculation (BIP141)
            wtxids.push(wtxid.toString("hex"));
          } else {
            wtxids.push(txJson.txid);
          }
        } else {
          console.log(
            `Skipping transaction ${txJson.txid} as it would exceed max block weight`
          );
        }
      } else {
        console.log(
          `Skipping invalid transaction ${txJson.txid}: ${result.error}`
        );
      }
    }

    console.log(`\nFound ${validTxs.length} valid transactions`);

    // 2. Select transactions for the block (prioritize by fee rate)
    console.log(`Sorting transactions by fee rate...`);
    validTxs.sort((a, b) => b.feeRate - a.feeRate);

    console.log(`Top transactions by fee rate:`);
    validTxs.forEach((tx, i) => {
      console.log(
        `  [${i}] ${tx.txid} - ${tx.feeRate.toFixed(2)} sat/vByte, ${
          tx.fee
        } sat fee`
      );
    });

    // 3. Calculate total fees
    const totalFees = validTxs.reduce((sum, tx) => sum + tx.fee, 0);
    console.log(`\nTotal fees from all transactions: ${totalFees} satoshis`);

    // 4. Create coinbase transaction
    const blockHeight = 835000; // Example block height
    console.log(`\nCreating block at height ${blockHeight}`);

    // Calculate witness commitment
    const witnessCommitment = calculateWitnessCommitment(wtxids);
    console.log(`Witness commitment: ${witnessCommitment}`);

    const coinbaseTx = createCoinbaseTransaction(
      blockHeight,
      totalFees,
      witnessCommitment
    );

    const coinbaseTxid = coinbaseTx.getId();
    const coinbaseTxHex = coinbaseTx.toHex();

    // 5. Create transaction ID list (coinbase first)
    const txids = [coinbaseTxid];
    for (const tx of validTxs) {
      txids.push(tx.txid);
    }

    console.log(`\nBlock will contain ${txids.length} transactions`);

    // 6. Calculate merkle root
    console.log(`\nCalculating Merkle root...`);
    const merkleRoot = generateMerkleRoot(txids);
    console.log(`Merkle root: ${merkleRoot.toString("hex")}`);

    // 7. Prepare block header
    console.log(`\nPreparing block header...`);
    const prevBlockHash =
      "0000000000000000000167a5f9c52325cf3190e4cd54d72fc4eba4a45993fac0"; // Example previous block hash
    const timestamp = Math.floor(Date.now() / 1000);
    const difficultyTarget =
      "0000ffff00000000000000000000000000000000000000000000000000000000"; // Example difficulty target
    const bits = "1f00ffff"; // Difficulty target in compact format

    // Parse target from bits
    const targetBuffer = Buffer.from(
      "0000ffff00000000000000000000000000000000000000000000000000000000",
      "hex"
    );

    // Create header template
    const headerTemplate = createBlockHeader(
      prevBlockHash,
      merkleRoot,
      timestamp,
      bits,
      0 // Initial nonce
    );

    // 8. Mine the block (find a valid nonce)
    console.log(`\nMining block...`);
    const minedBlock = mineBlock(headerTemplate, targetBuffer);

    // 9. Prepare output
    const serializedCoinbaseTx = serializeCoinbaseTransaction(coinbaseTx);
    console.log(
      "Serialized Coinbase Transaction:",
      serializedCoinbaseTx.toString("hex")
    );
    console.log(`\nPreparing output file...`);

    // Use the serialized transaction in your output
    const output = [
      minedBlock.header,
      serializedCoinbaseTx.toString("hex"),
      ...validTxs.map((tx) => tx.hex),
    ].join("\n");

    console.log(`Output has ${txids.length + 2} lines`);

    // 10. Write output file
    console.log(`Writing to output file: ${outputFile}`);
    await fs.writeFile(outputFile, output);

    console.log(`\n✅ Block successfully mined!`);
    console.log(`Block hash: ${minedBlock.hash}`);
    console.log(`Included ${validTxs.length} transactions (plus coinbase)`);
    console.log(`Output written to ${outputFile}`);

    return true;
  } catch (error) {
    console.error(`\n❌ Error mining block: ${error.message}`);
    console.error(error.stack);
    return false;
  }
}
console.log(
  `Starting Bitcoin mining simulation at ${new Date().toISOString()}`
);
processAndMineBlock()
  .then((success) => {
    if (success) {
      console.log(`\nMining simulation completed successfully!`);
    } else {
      console.log(`\nMining simulation failed.`);
    }
  })
  .catch((err) => {
    console.error(`\nCritical error in mining simulation:`, err);
  });

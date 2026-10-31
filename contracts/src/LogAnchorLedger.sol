// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

contract LogAnchorLedger {
    uint32 public constant CODEC_VERSION = 1;
    uint64 private constant MAX_SQLITE_ID = uint64(type(int64).max);
    uint32 private constant MAX_LEAVES = 5_000;

    struct Descriptor {
        uint32 codecVersion;
        bytes32 streamId;
        uint64 batchId;
        uint64 firstSeq;
        uint64 lastSeq;
        uint32 leafCount;
        bytes32 merkleRoot;
        bytes32 prevBatchHash;
    }

    struct Batch {
        uint64 firstSeq;
        uint64 lastSeq;
        uint32 leafCount;
        bytes32 merkleRoot;
        bytes32 prevBatchHash;
        bytes32 batchHash;
    }

    struct Head {
        uint64 batchId;
        uint64 lastSeq;
        bytes32 batchHash;
    }

    address public immutable owner;
    mapping(bytes32 => bytes32) public genesisHashes;
    mapping(bytes32 => address) public anchorAddresses;
    mapping(bytes32 => Head) private heads;
    mapping(bytes32 => mapping(uint64 => Batch)) private batches;

    error Unauthorized();
    error InvalidStream();
    error StreamAlreadyRegistered();
    error InvalidDescriptor();
    error BatchConflict();
    error BatchOutOfOrder();
    error PreviousHashMismatch();

    event StreamRegistered(bytes32 indexed streamId, bytes32 genesisHash, address indexed anchor);
    event BatchAnchored(
        bytes32 indexed streamId,
        uint64 indexed batchId,
        uint32 codecVersion,
        uint64 firstSeq,
        uint64 lastSeq,
        uint32 leafCount,
        bytes32 merkleRoot,
        bytes32 prevBatchHash,
        bytes32 batchHash
    );

    constructor() {
        owner = msg.sender;
    }

    function registerStream(bytes32 streamId, bytes32 genesisHash, address anchor) external {
        if (msg.sender != owner) revert Unauthorized();
        if (streamId == bytes32(0) || genesisHash == bytes32(0) || anchor == address(0)) revert InvalidStream();
        if (genesisHashes[streamId] != bytes32(0)) revert StreamAlreadyRegistered();
        genesisHashes[streamId] = genesisHash;
        anchorAddresses[streamId] = anchor;
        heads[streamId] = Head(0, 0, genesisHash);
        emit StreamRegistered(streamId, genesisHash, anchor);
    }

    function anchorBatch(Descriptor calldata d) external returns (bytes32 batchHash) {
        address anchor = anchorAddresses[d.streamId];
        if (anchor == address(0)) revert InvalidStream();
        if (msg.sender != anchor) revert Unauthorized();
        if (
            d.codecVersion != CODEC_VERSION || d.streamId == bytes32(0) || d.batchId == 0 || d.batchId > MAX_SQLITE_ID ||
            d.firstSeq == 0 || d.firstSeq > MAX_SQLITE_ID || d.lastSeq < d.firstSeq || d.lastSeq > MAX_SQLITE_ID ||
            d.leafCount == 0 || d.leafCount > MAX_LEAVES || d.lastSeq - d.firstSeq + 1 != d.leafCount || d.merkleRoot == bytes32(0)
        ) revert InvalidDescriptor();

        batchHash = sha256(abi.encode(d.codecVersion, d.streamId, d.batchId, d.firstSeq, d.lastSeq, d.leafCount, d.merkleRoot, d.prevBatchHash));
        Batch storage existing = batches[d.streamId][d.batchId];
        if (existing.batchHash != bytes32(0)) {
            if (
                existing.firstSeq != d.firstSeq || existing.lastSeq != d.lastSeq || existing.leafCount != d.leafCount ||
                existing.merkleRoot != d.merkleRoot || existing.prevBatchHash != d.prevBatchHash || existing.batchHash != batchHash
            ) revert BatchConflict();
            return batchHash;
        }

        Head storage head = heads[d.streamId];
        if (head.batchId == MAX_SQLITE_ID || d.batchId != head.batchId + 1 || head.lastSeq == MAX_SQLITE_ID || d.firstSeq != head.lastSeq + 1) revert BatchOutOfOrder();
        if (d.prevBatchHash != head.batchHash) revert PreviousHashMismatch();

        batches[d.streamId][d.batchId] = Batch(d.firstSeq, d.lastSeq, d.leafCount, d.merkleRoot, d.prevBatchHash, batchHash);
        heads[d.streamId] = Head(d.batchId, d.lastSeq, batchHash);
        emit BatchAnchored(d.streamId, d.batchId, d.codecVersion, d.firstSeq, d.lastSeq, d.leafCount, d.merkleRoot, d.prevBatchHash, batchHash);
    }

    function getBatch(bytes32 streamId, uint64 batchId) external view returns (Batch memory) {
        return batches[streamId][batchId];
    }

    function getHead(bytes32 streamId) external view returns (Head memory) {
        return heads[streamId];
    }
}

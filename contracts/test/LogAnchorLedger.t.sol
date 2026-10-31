// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import "../src/LogAnchorLedger.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
}

contract LogAnchorLedgerTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    LogAnchorLedger private ledger;
    bytes32 private constant STREAM = keccak256("stream");
    bytes32 private constant GENESIS = keccak256("genesis");
    address private constant ANCHOR = address(0xA11CE);

    function setUp() public {
        ledger = new LogAnchorLedger();
        ledger.registerStream(STREAM, GENESIS, ANCHOR);
    }

    function testAnchorsContiguousBatchAndExactRetry() public {
        LogAnchorLedger.Descriptor memory d = _batch(1, 1, 2, GENESIS);
        vm.prank(ANCHOR);
        bytes32 first = ledger.anchorBatch(d);
        vm.prank(ANCHOR);
        require(ledger.anchorBatch(d) == first, "retry changed hash");
        LogAnchorLedger.Head memory h = ledger.getHead(STREAM);
        require(h.batchId == 1 && h.lastSeq == 2 && h.batchHash == first, "wrong head");

        LogAnchorLedger.Descriptor memory next = _batch(2, 3, 3, first);
        vm.prank(ANCHOR);
        ledger.anchorBatch(next);
        require(ledger.getHead(STREAM).batchId == 2, "second batch missing");
    }

    function testRejectsUnauthorizedAndSkippedBatch() public {
        LogAnchorLedger.Descriptor memory d = _batch(1, 1, 1, GENESIS);
        vm.expectRevert(LogAnchorLedger.Unauthorized.selector);
        ledger.anchorBatch(d);

        d = _batch(2, 1, 1, GENESIS);
        vm.prank(ANCHOR);
        vm.expectRevert(LogAnchorLedger.BatchOutOfOrder.selector);
        ledger.anchorBatch(d);
    }

    function testRejectsConflictingRetryAndWrongParent() public {
        LogAnchorLedger.Descriptor memory d = _batch(1, 1, 1, GENESIS);
        vm.prank(ANCHOR);
        ledger.anchorBatch(d);
        d.merkleRoot = keccak256("different");
        vm.prank(ANCHOR);
        vm.expectRevert(LogAnchorLedger.BatchConflict.selector);
        ledger.anchorBatch(d);

        d = _batch(2, 2, 2, keccak256("wrong parent"));
        vm.prank(ANCHOR);
        vm.expectRevert(LogAnchorLedger.PreviousHashMismatch.selector);
        ledger.anchorBatch(d);
    }

    function testRejectsInvalidCountAndRange() public {
        LogAnchorLedger.Descriptor memory d = _batch(1, 1, 2, GENESIS);
        d.leafCount = 1;
        vm.prank(ANCHOR);
        vm.expectRevert(LogAnchorLedger.InvalidDescriptor.selector);
        ledger.anchorBatch(d);
    }

    function testBatchHashMatchesFrozenGoVector() public {
        bytes32 streamId = 0x1111111111111111111111111111111111111111111111111111111111111111;
        bytes32 root = 0xfb78c154747e7597380562a44bb74589a6d37a52130b4dd7b648366a18330944;
        bytes32 genesis = 0xb4f8b5cb482c7686c5a551ca7b7f005f4254e8bee4a6145f6bb10487f744e3ca;
        ledger.registerStream(streamId, genesis, ANCHOR);
        LogAnchorLedger.Descriptor memory d = LogAnchorLedger.Descriptor(1, streamId, 1, 1, 1, 1, root, genesis);
        vm.prank(ANCHOR);
        require(ledger.anchorBatch(d) == 0xba62ad8a52b8f13eafd096d78844995a164e1da58a9e5df24319b4155c857c25, "Go ABI vector mismatch");
    }

    function _batch(uint64 id, uint64 first, uint64 last, bytes32 parent) private view returns (LogAnchorLedger.Descriptor memory) {
        return LogAnchorLedger.Descriptor(1, STREAM, id, first, last, uint32(last - first + 1), keccak256(abi.encode(id)), parent);
    }
}
